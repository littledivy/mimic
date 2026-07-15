// The runtime every generated TypeScript client is built on — the TS parallel
// of mimic's Python `Session`/`App`. `mimic gen --lang ts` writes this file next
// to the generated client; the client imports { MimicClient } from "./mimic-runtime".
//
//   npm i axios zod
//
//   import { Hinge } from "./hinge_client";
//   const acc = Hinge.fromCurl(pastedCurl);   // or new Hinge({ baseUrl, headers })
//   await acc.getRecs();
//
// A MimicClient holds a base URL + reusable headers (your captured auth) and
// exposes get/post/... helpers that return parsed JSON. Generated subclasses add
// named methods and validate responses with Zod. On a 401 it re-auths once via an
// optional `refresh` callback — the TS equivalent of the app silently exchanging
// stored credentials for a fresh token — and retries idempotent methods.
import axios, { AxiosInstance, AxiosRequestConfig } from "axios";
import { ZodType } from "zod";

const IDEMPOTENT = new Set(["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]);

export type Headers = Record<string, string>;

export interface MimicOptions {
  baseUrl: string;
  headers?: Headers;
  /**
   * Called on a 401 to obtain a fresh header set (e.g. re-run a token exchange
   * with stored credentials). Return the new headers; return the same headers
   * (or throw) to decline the retry. Without it, a 401 is surfaced unchanged.
   */
  refresh?: () => Promise<Headers>;
}

export interface CallOptions<T> extends Omit<AxiosRequestConfig, "headers"> {
  /** Request body sent as JSON. */
  json?: unknown;
  /** Query parameters. */
  params?: Record<string, unknown>;
  /** Zod schema to validate + type the response body. Omit to return raw JSON. */
  schema?: ZodType<T>;
  /**
   * Force (`true`) or forbid (`false`) a single re-auth-and-retry on 401.
   * Defaults to allowing it only for idempotent methods.
   */
  refresh?: boolean;
  /** Per-call headers, merged over (not replacing) the session's auth headers. */
  headers?: Headers;
}

export class MimicClient {
  readonly baseUrl: string;
  protected headers: Headers;
  private readonly _refresh?: () => Promise<Headers>;
  private readonly http: AxiosInstance;

  constructor(opts: MimicOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.headers = { ...(opts.headers ?? {}) };
    this._refresh = opts.refresh;
    this.http = axios.create();
  }

  /** Build a client from a copied "Copy as cURL" string (browser devtools). */
  static fromCurl<T extends MimicClient>(
    this: new (opts: MimicOptions) => T,
    text: string,
    extra?: Partial<MimicOptions>,
  ): T {
    const { baseUrl, headers } = parseCurl(text);
    return new this({ baseUrl, headers, ...extra });
  }

  /**
   * Make a request and return its parsed body. Throws on non-2xx (after an
   * optional single 401 re-auth-and-retry). Validates against `schema` if given.
   */
  async request<T = unknown>(
    method: string,
    path: string,
    opts: CallOptions<T> = {},
  ): Promise<T> {
    const { json, params, schema, refresh, headers, ...rest } = opts;
    method = method.toUpperCase();
    const url = path.startsWith("http") ? path : `${this.baseUrl}${path}`;
    const allowRefresh = refresh === true || (refresh === undefined && IDEMPOTENT.has(method));

    try {
      const res = await this.http.request({
        method,
        url,
        // Merge per-call headers over the session's auth headers — never replace
        // them, or a caller setting e.g. Content-Type would drop the token.
        headers: { ...this.headers, ...headers },
        data: json,
        params,
        ...rest,
      });
      return schema ? schema.parse(res.data) : (res.data as T);
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 401 && allowRefresh && this._refresh) {
        // Retry only when refresh yields a non-empty, changed header set — so a
        // refresh miss doesn't downgrade into an unauthenticated retry.
        const next = await this._refresh();
        if (next && Object.keys(next).length && !sameHeaders(next, this.headers)) {
          this.headers = next;
          return this.request(method, path, { ...opts, refresh: false });
        }
      }
      throw err;
    }
  }

  get<T = unknown>(path: string, opts?: CallOptions<T>) {
    return this.request<T>("GET", path, opts);
  }
  post<T = unknown>(path: string, json?: unknown, opts?: CallOptions<T>) {
    return this.request<T>("POST", path, { ...opts, json });
  }
  put<T = unknown>(path: string, json?: unknown, opts?: CallOptions<T>) {
    return this.request<T>("PUT", path, { ...opts, json });
  }
  patch<T = unknown>(path: string, json?: unknown, opts?: CallOptions<T>) {
    return this.request<T>("PATCH", path, { ...opts, json });
  }
  delete<T = unknown>(path: string, opts?: CallOptions<T>) {
    return this.request<T>("DELETE", path, opts);
  }
  head<T = unknown>(path: string, opts?: CallOptions<T>) {
    return this.request<T>("HEAD", path, opts);
  }
  options<T = unknown>(path: string, opts?: CallOptions<T>) {
    return this.request<T>("OPTIONS", path, opts);
  }
}

function sameHeaders(a: Headers, b: Headers): boolean {
  const ak = Object.keys(a);
  if (ak.length !== Object.keys(b).length) return false;
  return ak.every((k) => a[k] === b[k]);
}

/** Minimal `curl 'URL' -H 'k: v' ...` parser for the paste fallback. */
export function parseCurl(text: string): { baseUrl: string; headers: Headers } {
  const tokens = tokenize(text.replace(/\\\n/g, " "));
  let url: string | undefined;
  const headers: Headers = {};
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "-H" || t === "--header") {
      const raw = tokens[++i] ?? "";
      const idx = raw.indexOf(":");
      // Mirror Python's str.partition(":"): a header with no colon keeps its
      // whole text as the key with an empty value.
      if (idx === -1) headers[raw.trim()] = "";
      else headers[raw.slice(0, idx).trim()] = raw.slice(idx + 1).trim();
    } else if (t.startsWith("http")) {
      url = t;
    }
  }
  if (!url) throw new Error("no URL found in cURL text");
  const u = new URL(url);
  return { baseUrl: `${u.protocol}//${u.host}`, headers };
}

/** Split a shell-ish string, honoring single and double quotes. */
function tokenize(text: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}
