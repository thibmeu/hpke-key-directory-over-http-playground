export function textToResponse(title: string, text: string) {
	const body = `<!DOCTYPE html>
<title>${title}</title>
<style>
pre {
	font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro',
		Menlo, Consolas, 'DejaVu Sans Mono', monospace;
}
:root {
	color-scheme: light dark;
}
.container {
	max-width: 800px;
	margin: 100px auto;
}
a {
  color: black;
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