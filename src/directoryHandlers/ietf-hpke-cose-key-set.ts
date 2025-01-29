import { Bindings } from "../bindings";
import { textToResponse } from "../html";

export async function handler(req: Request, env: Bindings): Promise<Response> {
    const text = `<a href="/">⮪</a>
# IETF HPKE Cose Key Set format

<a href="https://datatracker.ietf.org/doc/html/rfc8152#section-7">https://datatracker.ietf.org/doc/html/rfc8152#section-7</a>
<a href="https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-10">https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-10</a>

## Request
GET /ietf-hpke-cose/cose-key-set.cbor

## Response
Not implemented yet
`
    return textToResponse('Privacy Pass Format', text);
}