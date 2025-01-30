import { Bindings } from '../bindings';
import { hexEncode } from '../encoding/hex';
import { responseToInnerText, textToResponse } from '../html';
import { signatureKeys, StorageMetadata } from '../rotation';

export async function handler(req: Request, env: Bindings): Promise<Response> {
  // todo: consider cache

  const keys = await signatureKeys(env);

  const directory = {
    'issuer-request-uri': '/token-request',
    'token-keys': keys.map((key) => ({
      'token-type': '0x0002',
      'token-key': (key.customMetadata as StorageMetadata).publicKey,
      'not-before': Number.parseInt(
        (key.customMetadata as StorageMetadata).notBefore ?? (new Date(key.uploaded).getTime() / 1000).toFixed(0),
      ),
    })),
  };

  const body = JSON.stringify(directory, null, 2);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
  const etag = `"${hexEncode(digest)}"`;

  const response = new Response(body, {
    headers: {
      'content-type': 'application/private-token-issuer-directory',
      'cache-control': `public, max-age=${Number.parseInt(env.DIRECTORY_CACHE_MAX_AGE_SECONDS)}`,
      'content-length': body.length.toString(),
      date: new Date().toUTCString(),
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

## Notes
token-type is provided to meet Privacy Pass spec
`;
  return textToResponse('Privacy Pass Format', text);
}
