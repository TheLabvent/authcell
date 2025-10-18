export interface FiberResponse<T = any> {
	status: "success" | "error";
	code: number;
	message?: string;
	data?: T;
	error?: unknown;
	timestamp: number;
}

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

		// Handle top-level HTTP error
		if (!res.ok) {
			const errText = await res.text();
			throw new Error(`HTTP ${res.status}: ${errText}`);
		}

		const json: FiberResponse<T> = await res.json();

		// The server always sends status, code, timestamp.
		if (json.status === "error") {
			throw new Error(`Error ${json.code}: ${json.message || "unknown"}`);
		}

		// Return only the Data payload to preserve existing call pattern
		if (!json.data) {
			throw new Error("No data field in server response");
		}

		return json.data;
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
