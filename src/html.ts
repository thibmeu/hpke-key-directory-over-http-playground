export function textToResponse(title: string, text: string) {
	const body = `<!DOCTYPE html>
<title>${title}</title>
<link rel="icon" href="data:," />
<style>
pre {
	font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro',
		Menlo, Consolas, 'DejaVu Sans Mono', monospace;
    text-wrap: auto;
    word-break: break-all;
}
:root {
	color-scheme: light dark;
    --link-color: black;
}

@media (prefers-color-scheme: dark) {
  :root {
    --link-color: white;
  }
}
.container {
	max-width: 800px;
	margin: 100px auto;
}
a {
  color: var(--link-color);
}
a:hover {
  font-weight: bold;
}

</style>
<div class="container">
<pre>
${text}`
  return new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8' } })
}

export async function responseToInnerText(response: Response): Promise<string> {
    return `${[...response.headers.entries()].map(([key, value]) => `${key}: ${value}`).join('\n')}

${await response.text()}`
}