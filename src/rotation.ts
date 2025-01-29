import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { Bindings } from "./bindings";
import { convertEncToRSASSAPSS } from "./crypto";
import { b64ToB64URL, u8ToB64 } from "./encoding/base64";

type Params = {};

export class RotationWorkflow extends WorkflowEntrypoint<Bindings, Params> {
	async run(event: WorkflowEvent<Params>, step: WorkflowStep) {
		// Can access bindings on `this.env`
		// Can access params on `event.payload`

		const files = await step.do('my first step', async () => {
			// Fetch a list of files from $SOME_SERVICE
			return {
				inputParams: event,
				files: [
					'doc_7392_rev3.pdf',
					'report_x29_final.pdf',
					'memo_2024_05_12.pdf',
					'file_089_update.pdf',
					'proj_alpha_v2.pdf',
					'data_analysis_q2.pdf',
					'notes_meeting_52.pdf',
					'summary_fy24_draft.pdf',
				],
			};
		});

		const apiResponse = await step.do('some other step', async () => {
			let resp = await fetch('https://api.cloudflare.com/client/v4/ips');
			return await resp.json<any>();
		});

		await step.sleep('wait on something', '1 minute');

		await step.do(
			'make a call to write that could maybe, just might, fail',
			// Define a retry strategy
			{
				retries: {
					limit: 5,
					delay: '5 second',
					backoff: 'exponential',
				},
				timeout: '15 minutes',
			},
			async () => {
				// Do stuff here, with access to the state from our previous steps
				if (Math.random() > 0.5) {
					throw new Error('API call to $STORAGE_SYSTEM failed');
				}
			},
		);
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
};

export async function rotationHandler(env: Bindings): Promise<Response> {
	let publicKeyEnc: string;
	let tokenKeyID: number;
	let privateKey: ArrayBuffer;
	do {
		const keypair = (await crypto.subtle.generateKey(
			{
				name: 'RSA-PSS',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: { name: 'SHA-384' },
			},
			true,
			['sign', 'verify']
		)) as CryptoKeyPair;
		const publicKey = new Uint8Array(
			(await crypto.subtle.exportKey('spki', keypair.publicKey)) as ArrayBuffer
		);
		const rsaSsaPssPublicKey = convertEncToRSASSAPSS(publicKey);
		publicKeyEnc = b64ToB64URL(u8ToB64(rsaSsaPssPublicKey));
		tokenKeyID = await keyToTokenKeyID(rsaSsaPssPublicKey);
		privateKey = (await crypto.subtle.exportKey('pkcs8', keypair.privateKey)) as ArrayBuffer;
		// The bellow condition ensure there is no collision between truncated_token_key_id provided by the issuer
		// This is a 1/256 with 2 keys, and 256/256 chances with 256 keys. This means an issuer cannot have more than 256 keys at the same time.
		// Otherwise, this loop is going to be infinite. With 255 keys, this iteration might take a while.
	} while ((await env.KEYS.head(tokenKeyID.toString())) !== null);

	const metadata: StorageMetadata = {
		notBefore: ((Date.now() + Number.parseInt(env.KEY_NOT_BEFORE_DELAY_IN_MS)) / 1000).toFixed(
			0
		), // in unix seconds
		publicKey: publicKeyEnc,
		tokenKeyID: tokenKeyID.toString(),
	};

	await env.KEYS.put(tokenKeyID.toString(), privateKey, {
		customMetadata: metadata,
	});
    return new Response(publicKeyEnc)
}

export function shouldClearKey(keyNotBefore: Date, lifespanInMs: number): boolean {
	const keyExpirationTime = keyNotBefore.getTime() + lifespanInMs;
	return Date.now() > keyExpirationTime;
}

export async function clearKeyHandler(env: Bindings): Promise<Response> {
	const keys = await env.KEYS.list();

	if (keys.objects.length === 0) {
		return new Response('No keys to clear', { status: 201 });
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
		return new Response('No keys to clear', { status: 201 });
	}

	await env.KEYS.delete(toDeleteArray);

	return new Response(`Keys cleared: ${toDeleteArray.join('\n')}`, { status: 201 });
}