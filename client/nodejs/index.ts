export interface APIKeyCreateResponse {
	api_key: string;
	id: string;
	key_id: string;
}

export interface APIKeyVerifyResponse {
	valid: boolean;
}

export class AuthCellClient {
	private baseUrl: string;

	constructor(baseUrl?: string) {
		this.baseUrl =
			baseUrl || process.env.AUTHCELL_URL || "http://localhost:8080/v1";
	}

	private async __request<T>(
		path: string,
		method: string,
		body?: unknown,
	): Promise<T> {
		const headers = { "Content-Type": "application/json" };
		const url = `${this.baseUrl}${path}`;
		const res = await fetch(url, {
			method,
			headers,
			body: body ? JSON.stringify(body) : undefined,
		});
		if (!res.ok) {
			const err = await res.text();
			throw new Error(`HTTP ${res.status}: ${err}`);
		}
		const data = await res.json();
		return data.data as T;
	}

	async createKey(opts: {
		key_prefix: string;
		expires_at?: string;
		rate_limit?: number;
	}): Promise<APIKeyCreateResponse> {
		return this.__request<APIKeyCreateResponse>("/keys", "POST", opts);
	}

	async verifyKey(api_key: string): Promise<APIKeyVerifyResponse> {
		return this.__request<APIKeyVerifyResponse>("/keys/verify", "POST", {
			api_key,
		});
	}

	async getKey(id: string) {
		return this.__request(`/keys/${id}`, "GET");
	}

	async revokeKey(id: string) {
		return this.__request(`/keys/${id}`, "DELETE");
	}

	async listUsage(id: string) {
		return this.__request(`/usage/${id}`, "GET");
	}

	async listAuditLog() {
		return this.__request("/audit", "GET");
	}
}
