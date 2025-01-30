import { encode } from 'cbor2';
import { Bindings } from '../bindings';
import { convertRSASSAPSSToEnc } from '../crypto';
import { b64Tou8, b64URLtoB64 } from '../encoding/base64';
import { responseToInnerText, textToResponse } from '../html';
import { r2Keys, StorageMetadata } from '../rotation';
import { hexEncode } from '../encoding/hex';

export async function handler(req: Request, env: Bindings): Promise<Response> {
  const keys = await r2Keys(env);

  const keyToCoseKeyDecoded = async (key: R2Object) => {
    const metadata = key.customMetadata as StorageMetadata;
    const rsaSsaPssPublicKey = b64Tou8(b64URLtoB64(metadata.publicKey));
    const publicKeyEnc = convertRSASSAPSSToEnc(rsaSsaPssPublicKey);
    const publicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyEnc,
      {
        name: 'RSA-PSS',
        hash: { name: 'SHA-384' },
      },
      true,
      ['verify'],
    );
    const publicKeyJwk = (await crypto.subtle.exportKey('jwk', publicKey)) as JsonWebKey;

    // HPKE-1 37
    const publicKeyCoseKeyMap = new Map();
    publicKeyCoseKeyMap.set(1, 2); // EC2 https://www.rfc-editor.org/rfc/rfc8230.html
    publicKeyCoseKeyMap.set(2, new Uint8Array([Number.parseInt(metadata.tokenKeyID)]));
    publicKeyCoseKeyMap.set(3, 37); // HPKE-1  DHKEM(P-384, HKDF-SHA384) KEM, the HKDF-SHA384 KDF, and the AES-256-GCM AEAD
    // publicKeyCoseKeyMap.set(4, [3]); // not required for public keys - encrypt https://datatracker.ietf.org/doc/html/rfc8152#section-7.1
    publicKeyCoseKeyMap.set(-1, 2) // P-384 https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
    // TODO: generate a real key, don't reuse a signature scheme
    publicKeyCoseKeyMap.set(-2, b64Tou8(b64URLtoB64(publicKeyJwk.n!))); // MUST BE x
    publicKeyCoseKeyMap.set(-3, b64Tou8(b64URLtoB64(publicKeyJwk.e!))); // MUST BE y

    // List of arguments https://www.iana.org/assignments/jose/jose.xhtml
    return publicKeyCoseKeyMap;
  };

  const keysCoseDecoded = await Promise.all(keys.map((key) => keyToCoseKeyDecoded(key)));

  const directory = encode(keysCoseDecoded);

  const body = `+----------------------------------------+
| NOTE: binary data not shown in browser |
+----------------------------------------+

### COSE Key Set as hex
${hexEncode(directory)
  .match(/.{1,2}/g)!
  .join(' ')}

### COSE Key Set as JSON Map
${JSON.stringify(keysCoseDecoded.map(m => Object.fromEntries(m)), null, 2)}
`;

  const response = new Response(body, {
    headers: {
      'content-type': 'application/cose-key-set',
      'content-length': directory.length.toString(),
      date: new Date().toUTCString(),
    },
  });

  const text = `<a href="/">⮪</a>
# IETF HPKE Cose Key Set format

<a href="https://datatracker.ietf.org/doc/html/rfc8152#section-7">https://datatracker.ietf.org/doc/html/rfc8152#section-7</a>
<a href="https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-10">https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-10</a>

## Request
GET /ietf-hpke-cose/cose-key-set.cbor

## Response
${await responseToInnerText(response)}

## Notes
There does not seem to be a way to define not before based on <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA Cose registry</a>
kid can be any string. In this example, we enforce it to be the last byte of SHA256(base64url(publickey_rsassa))
No cache header defined
No rotation mechanism
`;
  return textToResponse('IETF HPKE Cose Key Set Format', text);
}
