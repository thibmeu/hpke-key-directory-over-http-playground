# Key Directory over HTTP playground

This playground aims to illustrate [Key Directory over HTTP specification](https://github.com/thibmeu/draft-darling-ohai-hpke-key-directory-over-http).

## Requirements

- Node.js 22+
- A Cloudflare account

## Deployment

1. Install packages

```shell
npm i
```

2. Create R2 key bucket

```shell
npx wrangler@latest r2 bucket create rotation-workflow
```

3. Deploy the worker

```shell
npm run deploy
```

## Development

- Start a local environment

```shell
npm run start
```

- Format with prettier

```shell
npm run format
```
