import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from 'cloudflare:workers';
import { Bindings } from './bindings';
import { convertEncToRSASSAPSS } from './crypto';
import { b64ToB64URL, u8ToB64 } from './encoding/base64';

type Params = {};

const KeyPrefix = {
  ENCRYPTION: 'enc-',
  SIGNATURES: 'sig-',
};

export async function encryptionKeys(env: Bindings): Promise<R2Object[]> {
  const keyList = await env.KEYS.list({ prefix: KeyPrefix.ENCRYPTION, include: ['customMetadata'] });

  if (keyList.objects.length === 0) {
    throw new Error('directory not initialised');
  }

  // there is no reason for an auditor to continue serving keys beyond the minimum requirement
  const freshestKeyCount = Number.parseInt(env.MINIMUM_FRESHEST_KEYS);
  const keys = keyList.objects.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime()).slice(0, freshestKeyCount);

  return keys;
}

export async function signatureKeys(env: Bindings): Promise<R2Object[]> {
  const keyList = await env.KEYS.list({ prefix: KeyPrefix.SIGNATURES, include: ['customMetadata'] });

  if (keyList.objects.length === 0) {
    throw new Error('directory not initialised');
  }

  // there is no reason for an auditor to continue serving keys beyond the minimum requirement
  const freshestKeyCount = Number.parseInt(env.MINIMUM_FRESHEST_KEYS);
  const keys = keyList.objects.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime()).slice(0, freshestKeyCount);

  return keys;
}

export class RotationWorkflow extends WorkflowEntrypoint<Bindings, Params> {
  async run(event: WorkflowEvent<Params>, step: WorkflowStep) {
    const env = this.env;

    const rotationEncryptionResponse = await step.do('rotate encryption keys', () => rotationByPrefix(env, KeyPrefix.ENCRYPTION));
    console.log(rotationEncryptionResponse);
    const rotationSignatureResponse = await step.do('rotate signature keys', () => rotationByPrefix(env, KeyPrefix.SIGNATURES));
    console.log(rotationSignatureResponse);
    const clearKeysResponse = await step.do('clear keys', async () => {
      const response = await clearKeyHandler(env);
      return response.text();
    });
    console.log(clearKeysResponse);
  }
}

export interface StorageMetadata extends Record<string, string> {
  notBefore: string;
  publicKey: string;
  tokenKeyID: string;
}

// this is from privacy pass specification. it needs to be correlated with HPKE
export async function keyToTokenKeyID(key: Uint8Array): Promise<number> {
  const hash = await crypto.subtle.digest('SHA-256', key);
  const u8 = new Uint8Array(hash);
  return u8[u8.length - 1];
}

async function generateKeyEncryption() {
  const keypair = (await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-384',
    },
    true,
    ['deriveBits', 'deriveKey'],
  )) as CryptoKeyPair;
  const publicKey = new Uint8Array((await crypto.subtle.exportKey('spki', keypair.publicKey)) as ArrayBuffer);
  const privateKey = new Uint8Array((await crypto.subtle.exportKey('pkcs8', keypair.privateKey)) as ArrayBuffer);

  return { publicKey, privateKey };
}

async function generateKeySignature() {
  const keypair = (await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: 'SHA-384' },
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const publicKey = new Uint8Array((await crypto.subtle.exportKey('spki', keypair.publicKey)) as ArrayBuffer);
  const rsaSsaPssPublicKey = convertEncToRSASSAPSS(publicKey);
  const privateKey = new Uint8Array((await crypto.subtle.exportKey('pkcs8', keypair.privateKey)) as ArrayBuffer);

  return { publicKey: rsaSsaPssPublicKey, privateKey };
}

export async function rotationByPrefix(env: Bindings, prefix: string = ''): Promise<string> {
  let generateKey: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
  if (prefix === KeyPrefix.ENCRYPTION) {
    generateKey = generateKeyEncryption;
  } else {
    generateKey = generateKeySignature;
  }

  let publicKeyEnc: string;
  let tokenKeyID: number;
  let privateKey: ArrayBuffer;
  do {
    const keypair = await generateKey();
    publicKeyEnc = b64ToB64URL(u8ToB64(keypair.publicKey));
    tokenKeyID = await keyToTokenKeyID(keypair.publicKey);
    privateKey = keypair.privateKey.buffer;
    // The bellow condition ensure there is no collision between truncated_token_key_id provided by the issuer
    // This is a 1/256 with 2 keys, and 256/256 chances with 256 keys. This means an issuer cannot have more than 256 keys at the same time.
    // Otherwise, this loop is going to be infinite. With 255 keys, this iteration might take a while.
  } while ((await env.KEYS.head(tokenKeyID.toString())) !== null);

  const metadata: StorageMetadata = {
    notBefore: ((Date.now() + Number.parseInt(env.KEY_NOT_BEFORE_DELAY_IN_MS)) / 1000).toFixed(0), // in unix seconds
    publicKey: publicKeyEnc,
    tokenKeyID: tokenKeyID.toString(),
  };

  await env.KEYS.put(`${prefix}${tokenKeyID.toString()}`, privateKey, {
    customMetadata: metadata,
  });
  return publicKeyEnc;
}

export async function rotationHandler(env: Bindings): Promise<Response> {
  const publicKeyEncryption = await rotationByPrefix(env, KeyPrefix.ENCRYPTION);
  const publicKeySignature = await rotationByPrefix(env, KeyPrefix.SIGNATURES);

  return new Response(`new encryption key: ${publicKeyEncryption}\nnew signature key: ${publicKeySignature}`);
}

export function shouldClearKey(keyNotBefore: Date, lifespanInMs: number): boolean {
  const keyExpirationTime = keyNotBefore.getTime() + lifespanInMs;
  return Date.now() > keyExpirationTime;
}

export async function clearKeyByPrefix(env: Bindings, prefix: string): Promise<string[]> {
  const keys = await env.KEYS.list({ prefix });

  if (keys.objects.length === 0) {
    return [];
  }

  const lifespanInMs = Number.parseInt(env.KEY_LIFESPAN_IN_MS);
  const freshestKeyCount = Number.parseInt(env.MINIMUM_FRESHEST_KEYS);

  keys.objects.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime());

  const toDelete: Set<string> = new Set();

  for (let i = 0; i < keys.objects.length; i++) {
    const key = keys.objects[i];
    const notBefore = key.customMetadata?.notBefore;
    let keyNotBefore: Date;
    if (notBefore) {
      keyNotBefore = new Date(Number.parseInt(notBefore) * 1000);
    } else {
      keyNotBefore = new Date(key.uploaded);
    }

    const isFreshest = i < freshestKeyCount;

    if (isFreshest) {
      continue;
    }

    const shouldDelete = shouldClearKey(keyNotBefore, lifespanInMs);

    if (shouldDelete) {
      toDelete.add(key.key);
    }
  }

  const toDeleteArray = [...toDelete];

  if (toDeleteArray.length === 0) {
    return [];
  }

  await env.KEYS.delete(toDeleteArray);

  return toDeleteArray;
}

export async function clearKeyHandler(env: Bindings): Promise<Response> {
  const [deletedEnc, deletedSig] = await Promise.all([
    clearKeyByPrefix(env, KeyPrefix.ENCRYPTION),
    clearKeyByPrefix(env, KeyPrefix.SIGNATURES),
  ]);
  const deleted = [...deletedEnc, ...deletedSig];

  return new Response(`Keys cleared: ${deleted.join('\n')}`, { status: 201 });
}
