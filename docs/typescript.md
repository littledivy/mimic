# TypeScript output (`--lang ts`)

`mimic gen <host> --lang ts` generates a typed client for Node, the browser, or
React Native instead of the default Python one. It is the same pipeline —
capture your own traffic, let the AI read the endpoints — with an Axios + Zod
client as the output.

```bash
mimic gen prod-api.hingeaws.net --lang ts
# wrote prod_api_client.ts
# wrote ./mimic-runtime.ts  (runtime — commit it alongside the client)
```

Two files land next to each other:

- **`<host>_client.ts`** — the generated client. One exported class that
  `extends MimicClient`, one Zod schema per endpoint, and a named async method
  per real action. You edit this like any other source file.
- **`mimic-runtime.ts`** — the runtime, copied from mimic. The TS parallel of the
  Python `mimic.App` base class. It is regeneration-safe: if the file already
  exists it is left untouched, so local edits survive re-running `gen`.

```bash
npm i axios zod        # peer dependencies of the runtime
```

## Using a generated client

The client holds your captured auth (a base URL + a bundle of headers) and
exposes typed methods:

```ts
import { Hinge } from "./hinge_client";

const acc = new Hinge({
  baseUrl: "https://prod-api.hingeaws.net",
  headers: { authorization: "Bearer …", "x-device-id": "…" },
});

const recs = await acc.getRecs();   // return type inferred from the Zod schema
await acc.like(recs.subjects[0].id);
```

Or build it from a copied cURL (devtools → right-click a request → Copy as cURL):

```ts
const acc = Hinge.fromCurl(pastedCurlString);
```

## Getting the session

The Python client can auto-pull auth from mitmweb because it runs on the same
machine as the proxy. A TypeScript client usually runs somewhere else (a Node
script, an app), so it takes its session **explicitly** — via the constructor or
`fromCurl`. Capture the headers however you like: mimic's mitmweb dashboard,
`Copy as cURL`, or a HAR export.

## Validation and types

Each endpoint gets a Zod schema inferred from the captured response body:

```ts
const RecsSchema = z.object({
  subjects: z.array(z.object({ id: z.string() })),
  viewToken: z.string().nullable(),
});
export type Recs = z.infer<typeof RecsSchema>;
```

Methods pass their schema through, so the response is validated at runtime and
typed at compile time:

```ts
getRecs(): Promise<Recs> {
  return this.get("/rec/v2", { schema: RecsSchema });
}
```

Captured bodies are only a sample, so treat generated schemas as a starting
point — loosen a field to `.optional()` / `.nullable()` or `z.unknown()` when the
real API is more varied than the one response mimic saw. Omit `schema` entirely
to get the raw parsed JSON back untyped.

## Silent re-auth on 401

The runtime retries a `401` once on idempotent methods (and on any method when
you pass `{ refresh: true }`) — but only if you gave it a way to get fresh
credentials. Because there's no mitmweb to re-pull from, you supply a `refresh`
callback returning a new header set:

```ts
const acc = new Hinge({
  baseUrl,
  headers,
  refresh: async () => {
    const token = await exchangeStoredCredentials();   // your token flow
    return { ...headers, authorization: `Bearer ${token}` };
  },
});
```

Return the same headers (or throw) to decline the retry. Without a `refresh`
callback, a `401` is surfaced unchanged.

## Limitations

The [capture-side limits](pinning.md) — certificate pinning and
[DPoP](dpop.md) — apply identically; they are properties of the target app, not
the output language. The one runtime difference is auth acquisition: Python can
pull from mitmweb, TypeScript is given the session explicitly.
