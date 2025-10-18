from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional, Type, TypeVar

T = TypeVar("T")


@dataclass
class FiberResponse:
    status: str
    code: int
    message: Optional[str] = None
    data: Optional[Any] = None
    error: Optional[Any] = None
    timestamp: Optional[int] = None


@dataclass
class APIKeyCreateResponse:
    api_key: str
    id: str
    key_id: str


@dataclass
class APIKeyVerifyResponse:
    valid: bool


# ---------------------- Client ----------------------


class AuthCellClient:
    def __init__(self, base_url: Optional[str] = None) -> None:
        """Initialize client with base URL or autodetect from ENV."""
        self.base_url = (
            base_url or os.getenv("AUTHCELL_URL") or "http://localhost:8080/v1"
        )

    def _request(
        self,
        path: str,
        method: str,
        body: Optional[Dict[str, Any]] = None,
        response_type: Optional[Type[T]] = None,
    ) -> T:
        """Core request handler for AuthCell."""
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body else None

        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                raw = resp.read().decode()
                if resp.status not in (200, 201):
                    raise RuntimeError(f"HTTP {resp.status}: {raw}")

                # Parse standard response structure
                parsed = json.loads(raw)
                fiber_resp = FiberResponse(**parsed)

                if fiber_resp.status == "error":
                    raise RuntimeError(
                        f"ServerError {fiber_resp.code}: {fiber_resp.message or fiber_resp.error}"
                    )

                if not fiber_resp.data:
                    raise RuntimeError("Response missing 'data' field")

                # Deserialize into response dataclass if type provided
                data_part = fiber_resp.data
                if response_type is not None:
                    # Ensure it's a dict before unpacking
                    if isinstance(data_part, dict):
                        return response_type(**data_part)
                    elif isinstance(data_part, list):
                        return data_part  # raw list for endpoints like audits
                return data_part
        except urllib.error.HTTPError as e:
            error_msg = e.read().decode()
            raise RuntimeError(f"HTTPError {e.code}: {error_msg}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"ConnectionError: {str(e)}")

    # ---------------------- API Methods ----------------------

    def create_key(
        self,
        key_prefix: str,
        expires_at: Optional[str] = None,
        rate_limit: Optional[int] = None,
    ) -> APIKeyCreateResponse:
        body = {
            "key_prefix": key_prefix,
            "expires_at": expires_at,
            "rate_limit": rate_limit,
        }
        return self._request("/keys", "POST", body, response_type=APIKeyCreateResponse)

    def verify_key(self, api_key: str) -> APIKeyVerifyResponse:
        return self._request(
            "/keys/verify",
            "POST",
            {"api_key": api_key},
            response_type=APIKeyVerifyResponse,
        )

    def get_key(self, key_id: str) -> Dict[str, Any]:
        return self._request(f"/keys/{key_id}", "GET")

    def revoke_key(self, key_id: str) -> Dict[str, Any]:
        return self._request(f"/keys/{key_id}", "DELETE")

    def list_usage(self, key_id: str) -> Dict[str, Any]:
        return self._request(f"/usage/{key_id}", "GET")

    def list_audit_log(self) -> Dict[str, Any]:
        return self._request("/audit", "GET")
