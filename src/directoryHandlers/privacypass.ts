import { Bindings } from "../bindings";
import { hexEncode } from "../encoding/hex";
import { responseToInnerText, textToResponse } from "../html";
import { StorageMetadata } from "../rotation";

export async function handler(req: Request, env: Bindings): Promise<Response> {
    // todo: consider cache

	const keyList = await env.KEYS.list({ include: ['customMetadata'] });

	if (keyList.objects.length === 0) {
		throw new Error('directory not initialised');
	}

	// there is no reason for an auditor to continue serving keys beyond the minimum requirement
	const freshestKeyCount = Number.parseInt(env.MINIMUM_FRESHEST_KEYS);
	const keys = keyList.objects
		.sort((a, b) => new Date(b.uploaded).getTime() - new Date(a.uploaded).getTime())
		.slice(0, freshestKeyCount);

	const directory = {
		'issuer-request-uri': '/token-request',
		'token-keys': keys.map(key => ({
			'token-type': "0x0002",
			'token-key': (key.customMetadata as StorageMetadata).publicKey,
			'not-before': Number.parseInt(
				(key.customMetadata as StorageMetadata).notBefore ??
					(new Date(key.uploaded).getTime() / 1000).toFixed(0)
			),
		})),
	};

	const body = JSON.stringify(directory, null, 2);
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
	);
	const etag = `"${hexEncode(digest)}"`;

	const response = new Response(body, {
		headers: {
			'content-type': "text/plain", // text/plain so people can see a response
			'cache-control': `public, max-age=${Number.parseInt(env.DIRECTORY_CACHE_MAX_AGE_SECONDS)}`,
			'content-length': body.length.toString(),
			'date': new Date().toUTCString(),
			etag,
		},
	});

    const text = `<a href="/">⮪</a>
# Privacy Pass format

<a href="https://www.rfc-editor.org/rfc/rfc9578.html#name-configuration">https://www.rfc-editor.org/rfc/rfc9578.html#name-configuration</a>

## Request
GET /.well-known/private-token-issuer-directory

## Response
${await responseToInnerText(response)}
`
	return textToResponse('Privacy Pass Format', text);
}