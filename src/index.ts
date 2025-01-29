import { AutoRouter } from 'itty-router';

import { handler as jwksHandler } from './directoryHandlers/jwks';
import { handler as privacypassHandler } from './directoryHandlers/privacypass';
import { handler as rotationHandler } from './rotation';
import { Env } from './bindings';
import { textToResponse } from './html';

export * from './rotation'

const router = AutoRouter()

export function handleHead <T extends (request: Request, env: Env) => Promise<Response>>(f: T): T {
	return (async (request, env) => {
		const response = await f(request, env)
		return new Response(undefined, {
			status: response.status,
			headers: response.headers,
		})
	}) as T
};

export function index() {
	const body = `# HPKE Key Directory over HTTP

github.com/thibmeu/hpke-key-directory-over-http-playground

## Endpoints

<a href="/.well-known/jwks.json">GET /.well-known/jwks.json</a>
<a href="/.well-known/private-token-key-directory">GET /.well-known/private-token-key-directory</a>
`
  return textToResponse(`HPKE Key Directory over HTTP`, body)
}

router
  .get('/', index)
  .head('/.well-known/jwks.json', handleHead(jwksHandler))
  .get('/.well-known/jwks.json', jwksHandler)
  .head('/.well-known/private-token-key-directory', handleHead(privacypassHandler))
  .get('/.well-known/private-token-key-directory', privacypassHandler)
  .post('/admin/rotate', rotationHandler)
  .all('*', () => Response.redirect('/'))

export default { ...router }
