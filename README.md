# BUN, Hono And HTMX Example

Stopped development of this project because it can not
be deployed to vercel.
Vercel is serverless and only supports a number of frameworks and
hono is not serverless and needs the server running all the time.
Found this out then I tried deploying to vercel and only saw the
built js code and not the output of the running js code.

I selected Hono vs Elysia because it is marginally slower than Elysia
and run on node vs bun which should make running node packages easier.
Bun does have a node compatibility layer and should work with most/"all"
node packages but I did not want to risk it for auth and db orm integration.

Release procedure for AWS are documented at:
`/intent/pages/docs/machines/aws/aws-ex1/README.md`

## Code History

The in this repository is based on:

- https://youtu.be/MzE30nkEZnc?si=IrNDf_DvApqfilsn

## Creation History

```bash
bunx create-hono bun-hono-htmx
cd bun-hono-htmx/
bun install
bun install -d @faker-js/faker
bun install @hono/node-server
bun install -d tailwindcss concurrently
```
