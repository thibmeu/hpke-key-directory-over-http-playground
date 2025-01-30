import { Bindings } from '../bindings';
import { textToResponse } from '../html';

export async function handler(req: Request, env: Bindings): Promise<Response> {
  const text = `<a href="/">⮪</a>
# IETF HPKE JWKS format

<a href="https://datatracker.ietf.org/doc/html/rfc7517">https://datatracker.ietf.org/doc/html/rfc7517</a>
<a href="https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-07">https://datatracker.ietf.org/doc/html/draft-rha-jose-hpke-encrypt-07</a>

## Request
GET /ietf-hpke-jose/jwks.json

## Response
Not implemented yet
`;
  return textToResponse('Privacy Pass Format', text);
}
