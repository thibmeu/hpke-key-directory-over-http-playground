import { Bindings } from '../bindings';
import { textToResponse } from '../html';

export async function handler(req: Request, env: Bindings): Promise<Response> {
  const text = `<a href="/">⮪</a>
# OpenID Connect JWKS format

<a href="https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys">https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys</a>

## Request
GET /openid-connect/jwks.json

## Response
Not implemented yet
`;
  return textToResponse('Privacy Pass Format', text);
}
