/**
 * AuthCell client for Node.js 18+ (uses native fetch, zero dependencies).
 *
 * Config comes from the constructor or these environment variables:
 *   AUTHCELL_URL          default http://localhost:8080/v1
 *   AUTHCELL_ADMIN_TOKEN  needed for management calls (create, list, revoke...)
 *   AUTHCELL_VERIFY_TOKEN only if the server sets one for /keys/verify
 */

export interface Envelope<T = unknown> {
	status: "success" | "error";
	code: number;
	message?: string;
	data?: T;
	meta?: Record<string, unknown>;
	timestamp: number;
}

export interface APIKey {
	id: string;
	key_id: string;
	key_prefix: string;
	name: string;
	metadata: Record<string, unknown>;
	is_active: boolean;
	created_at: string;
	expires_at: string | null;
	revoked_at: string | null;
	last_used_at: string | null;
	/** Max verifications per server window. 0 = unlimited. */
	rate_limit: number;
	usage_count: number;
}

/** Returned by create and rotate. `api_key` is shown only this once. */
export interface CreatedAPIKey extends APIKey {
	api_key: string;
}

export interface CreateKeyOptions {
	key_prefix?: string;
	name?: string;
	metadata?: Record<string, unknown>;
	expires_at?: string | Date;
	rate_limit?: number;
}

export interface UpdateKeyOptions {
	name?: string;
	metadata?: Record<string, unknown>;
	/** Pass null to remove the expiry. */
	expires_at?: string | Date | null;
	rate_limit?: number;
}

export type VerifyFailureReason = "invalid" | "revoked" | "expired" | "rate_limited";

export type VerifyResult =
	| {
			valid: true;
			id: string;
			key_id: string;
			key_prefix: string;
			name: string;
			metadata: Record<string, unknown>;
			expires_at: string | null;
			rate_limit: { limit: number; remaining: number; reset: string } | null;
	  }
	| { valid: false; reason: VerifyFailureReason };

export interface UsageRecord {
	id: number;
	api_key_id: string | null;
	endpoint: string;
	used_at: string;
	status: number;
	remote_ip: string | null;
}

export interface AuditRecord {
	id: number;
	actor_id: string | null;
	actor_type: string;
	event_type: string;
	event_data: Record<string, unknown>;
	event_time: string;
	remote_ip: string | null;
}

export interface Page<T> {
	data: T[];
	meta: Record<string, unknown>;
}

export interface ClientOptions {
	baseUrl?: string;
	adminToken?: string;
	verifyToken?: string;
	/** Request timeout in ms. Default 5000. */
	timeoutMs?: number;
}

export class AuthCellError extends Error {
	constructor(
		message: string,
		public readonly status: number,
		public readonly body?: Envelope,
	) {
		super(message);
		this.name = "AuthCellError";
	}
}

type Query = Record<string, string | number | boolean | undefined>;

export class AuthCellClient {
	private readonly baseUrl: string;
	private readonly adminToken?: string;
	private readonly verifyToken?: string;
	private readonly timeoutMs: number;

	constructor(opts: ClientOptions | string = {}) {
		const o: ClientOptions = typeof opts === "string" ? { baseUrl: opts } : opts;
		const env = typeof process !== "undefined" ? process.env : {};
		this.baseUrl = (o.baseUrl || env.AUTHCELL_URL || "http://localhost:8080/v1").replace(/\/+$/, "");
		this.adminToken = o.adminToken || env.AUTHCELL_ADMIN_TOKEN || undefined;
		this.verifyToken = o.verifyToken || env.AUTHCELL_VERIFY_TOKEN || undefined;
		this.timeoutMs = o.timeoutMs ?? 5000;
	}

	private async send<T>(
		method: string,
		path: string,
		opts: { body?: unknown; query?: Query; token?: string } = {},
	): Promise<{ status: number; env: Envelope<T> }> {
		const url = new URL(this.baseUrl + path);
		for (const [k, v] of Object.entries(opts.query ?? {})) {
			if (v !== undefined) url.searchParams.set(k, String(v));
		}
		const headers: Record<string, string> = { Accept: "application/json" };
		if (opts.body !== undefined) headers["Content-Type"] = "application/json";
		if (opts.token) headers.Authorization = `Bearer ${opts.token}`;

		let res: Response;
		try {
			res = await fetch(url, {
				method,
				headers,
				body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
				signal: AbortSignal.timeout(this.timeoutMs),
			});
		} catch (err) {
			throw new AuthCellError(`AuthCell unreachable at ${url.origin}: ${(err as Error).message}`, 0);
		}

		const text = await res.text();
		let env: Envelope<T>;
		try {
			env = JSON.parse(text);
		} catch {
			throw new AuthCellError(`HTTP ${res.status}: ${text.slice(0, 200)}`, res.status);
		}
		return { status: res.status, env };
	}

	private async admin<T>(method: string, path: string, body?: unknown, query?: Query): Promise<Envelope<T>> {
		if (!this.adminToken) {
			throw new AuthCellError("adminToken (or AUTHCELL_ADMIN_TOKEN) is required for this call", 0);
		}
		const { status, env } = await this.send<T>(method, path, { body, query, token: this.adminToken });
		if (status >= 400 || env.status === "error") {
			throw new AuthCellError(env.message || `HTTP ${status}`, status, env);
		}
		return env;
	}

	/** Verify a key. Never throws for an invalid key; check `result.valid`. */
	async verifyKey(apiKey: string): Promise<VerifyResult> {
		const { status, env } = await this.send<VerifyResult>("POST", "/keys/verify", {
			body: { api_key: apiKey },
			token: this.verifyToken,
		});
		if ((status === 401 || status === 429) && env.data && "valid" in env.data) {
			return env.data;
		}
		if (status === 400) return { valid: false, reason: "invalid" };
		if (status !== 200 || !env.data) {
			throw new AuthCellError(env.message || `HTTP ${status}`, status, env);
		}
		return env.data;
	}

	async createKey(opts: CreateKeyOptions = {}): Promise<CreatedAPIKey> {
		const body = { ...opts, expires_at: toISO(opts.expires_at) };
		return (await this.admin<CreatedAPIKey>("POST", "/keys", body)).data!;
	}

	async listKeys(opts: { limit?: number; offset?: number; active?: boolean; prefix?: string } = {}): Promise<Page<APIKey>> {
		const env = await this.admin<APIKey[]>("GET", "/keys", undefined, opts);
		return { data: env.data ?? [], meta: env.meta ?? {} };
	}

	async getKey(id: string): Promise<APIKey> {
		return (await this.admin<APIKey>("GET", `/keys/${encodeURIComponent(id)}`)).data!;
	}

	async updateKey(id: string, opts: UpdateKeyOptions): Promise<APIKey> {
		const body: Record<string, unknown> = { ...opts };
		if (opts.expires_at !== undefined) body.expires_at = opts.expires_at === null ? null : toISO(opts.expires_at);
		return (await this.admin<APIKey>("PATCH", `/keys/${encodeURIComponent(id)}`, body)).data!;
	}

	async revokeKey(id: string): Promise<APIKey> {
		return (await this.admin<APIKey>("DELETE", `/keys/${encodeURIComponent(id)}`)).data!;
	}

	/** Issue a replacement key with the same settings and revoke the old one. */
	async rotateKey(id: string): Promise<CreatedAPIKey> {
		return (await this.admin<CreatedAPIKey>("POST", `/keys/${encodeURIComponent(id)}/rotate`)).data!;
	}

	async listUsage(id: string, opts: { limit?: number; before?: number } = {}): Promise<Page<UsageRecord>> {
		const env = await this.admin<UsageRecord[]>("GET", `/usage/${encodeURIComponent(id)}`, undefined, opts);
		return { data: env.data ?? [], meta: env.meta ?? {} };
	}

	async listAuditLog(opts: { limit?: number; before?: number; event_type?: string } = {}): Promise<Page<AuditRecord>> {
		const env = await this.admin<AuditRecord[]>("GET", "/audit", undefined, opts);
		return { data: env.data ?? [], meta: env.meta ?? {} };
	}

	async health(): Promise<Record<string, unknown>> {
		const { status, env } = await this.send<Record<string, unknown>>("GET", "/health");
		if (status !== 200) throw new AuthCellError(env.message || `HTTP ${status}`, status, env);
		return env.data ?? {};
	}
}

function toISO(v: string | Date | undefined): string | undefined {
	if (v === undefined) return undefined;
	return v instanceof Date ? v.toISOString() : v;
}
