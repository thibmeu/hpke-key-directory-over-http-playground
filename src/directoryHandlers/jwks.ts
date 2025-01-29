import { Env } from "../bindings";
import { textToResponse } from "../html";

export async function handler(req: Request, env: Env): Promise<Response> {
    const text = `<a href="/">⮪</a>
# OpenID Connect JWKS format

https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys

## Request
GET /.well-known/jwks.json

## Response
Not implemented yet
`
    return textToResponse('Privacy Pass Format', text);
}