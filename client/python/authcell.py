"""AuthCell client for Python 3.8+ (standard library only).

Config comes from the constructor or these environment variables:
    AUTHCELL_URL           default http://localhost:8080/v1
    AUTHCELL_ADMIN_TOKEN   needed for management calls (create, list, revoke...)
    AUTHCELL_VERIFY_TOKEN  only if the server sets one for /keys/verify
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

__all__ = [
    "AuthCellClient",
    "AuthCellError",
    "APIKey",
    "CreatedAPIKey",
    "VerifyResult",
    "Page",
]

_UNSET: Any = object()


class AuthCellError(Exception):
    """Raised for transport errors and non-verify API errors."""

    def __init__(self, message: str, status: int = 0, body: Optional[dict] = None):
        super().__init__(message)
        self.status = status
        self.body = body or {}


def _from_dict(cls, data: Dict[str, Any]):
    """Build a dataclass, ignoring fields the server adds in future versions."""
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


@dataclass
class APIKey:
    id: str
    key_id: str
    key_prefix: str
    name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None
    rate_limit: int = 0
    usage_count: int = 0


@dataclass
class CreatedAPIKey(APIKey):
    #: The plaintext key. Returned only once; store it securely.
    api_key: str = ""


@dataclass
class VerifyResult:
    valid: bool
    reason: Optional[str] = None
    id: Optional[str] = None
    key_id: Optional[str] = None
    key_prefix: Optional[str] = None
    name: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None
    rate_limit: Optional[Dict[str, Any]] = None

    def __bool__(self) -> bool:
        return self.valid


@dataclass
class Page:
    data: List[Dict[str, Any]]
    meta: Dict[str, Any]


def _iso(v: Union[str, datetime, None]) -> Optional[str]:
    if isinstance(v, datetime):
        if v.tzinfo is None:
            raise ValueError("expires_at datetime must be timezone-aware")
        return v.isoformat()
    return v


class AuthCellClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        admin_token: Optional[str] = None,
        verify_token: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("AUTHCELL_URL") or "http://localhost:8080/v1"
        ).rstrip("/")
        self.admin_token = admin_token or os.getenv("AUTHCELL_ADMIN_TOKEN") or None
        self.verify_token = verify_token or os.getenv("AUTHCELL_VERIFY_TOKEN") or None
        self.timeout = timeout

    # ------------------------------------------------------------------ core

    def _send(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        url = self.base_url + path
        if query:
            q = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q)

        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise AuthCellError(f"AuthCell unreachable at {self.base_url}: {e}") from e

        try:
            env = json.loads(raw.decode("utf-8") or "{}")
        except ValueError:
            raise AuthCellError(f"HTTP {status}: {raw[:200]!r}", status)
        return status, env

    def _admin(self, method: str, path: str, body=None, query=None) -> Dict[str, Any]:
        if not self.admin_token:
            raise AuthCellError("admin_token (or AUTHCELL_ADMIN_TOKEN) is required for this call")
        status, env = self._send(method, path, body, query, self.admin_token)
        if status >= 400 or env.get("status") == "error":
            raise AuthCellError(env.get("message") or f"HTTP {status}", status, env)
        return env

    @staticmethod
    def _quote(v: str) -> str:
        return urllib.parse.quote(v, safe="")

    # ------------------------------------------------------------------ verify

    def verify_key(self, api_key: str) -> VerifyResult:
        """Verify a key. Never raises for an invalid key; check ``result.valid``."""
        status, env = self._send("POST", "/keys/verify", {"api_key": api_key}, token=self.verify_token)
        data = env.get("data")
        if status in (401, 429) and isinstance(data, dict) and "valid" in data:
            return _from_dict(VerifyResult, data)
        if status == 400:
            return VerifyResult(valid=False, reason="invalid")
        if status != 200 or not isinstance(data, dict):
            raise AuthCellError(env.get("message") or f"HTTP {status}", status, env)
        return _from_dict(VerifyResult, data)

    # ------------------------------------------------------------------ keys

    def create_key(
        self,
        key_prefix: str = "",
        name: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        expires_at: Union[str, datetime, None] = None,
        rate_limit: Optional[int] = None,
    ) -> CreatedAPIKey:
        body: Dict[str, Any] = {"key_prefix": key_prefix, "name": name}
        if metadata is not None:
            body["metadata"] = metadata
        if expires_at is not None:
            body["expires_at"] = _iso(expires_at)
        if rate_limit is not None:
            body["rate_limit"] = rate_limit
        return _from_dict(CreatedAPIKey, self._admin("POST", "/keys", body)["data"])

    def list_keys(
        self,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        active: Optional[bool] = None,
        prefix: Optional[str] = None,
    ) -> Page:
        env = self._admin("GET", "/keys", query={"limit": limit, "offset": offset, "active": active, "prefix": prefix})
        return Page(env.get("data") or [], env.get("meta") or {})

    def get_key(self, id: str) -> APIKey:
        return _from_dict(APIKey, self._admin("GET", f"/keys/{self._quote(id)}")["data"])

    def update_key(
        self,
        id: str,
        name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expires_at: Any = _UNSET,
        rate_limit: Optional[int] = None,
    ) -> APIKey:
        """Update a key. Pass ``expires_at=None`` to remove its expiry."""
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if metadata is not None:
            body["metadata"] = metadata
        if expires_at is not _UNSET:
            body["expires_at"] = _iso(expires_at)
        if rate_limit is not None:
            body["rate_limit"] = rate_limit
        return _from_dict(APIKey, self._admin("PATCH", f"/keys/{self._quote(id)}", body)["data"])

    def revoke_key(self, id: str) -> APIKey:
        return _from_dict(APIKey, self._admin("DELETE", f"/keys/{self._quote(id)}")["data"])

    def rotate_key(self, id: str) -> CreatedAPIKey:
        """Issue a replacement key with the same settings and revoke the old one."""
        return _from_dict(CreatedAPIKey, self._admin("POST", f"/keys/{self._quote(id)}/rotate")["data"])

    # ------------------------------------------------------------------ logs

    def list_usage(self, id: str, limit: Optional[int] = None, before: Optional[int] = None) -> Page:
        env = self._admin("GET", f"/usage/{self._quote(id)}", query={"limit": limit, "before": before})
        return Page(env.get("data") or [], env.get("meta") or {})

    def list_audit_log(
        self, limit: Optional[int] = None, before: Optional[int] = None, event_type: Optional[str] = None
    ) -> Page:
        env = self._admin("GET", "/audit", query={"limit": limit, "before": before, "event_type": event_type})
        return Page(env.get("data") or [], env.get("meta") or {})

    def health(self) -> Dict[str, Any]:
        status, env = self._send("GET", "/health")
        if status != 200:
            raise AuthCellError(env.get("message") or f"HTTP {status}", status, env)
        return env.get("data") or {}
