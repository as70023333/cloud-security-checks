"""A small HTTP client built on the standard library.

Retries 429 and 5xx responses (honouring Retry-After), retries network errors with
exponential backoff and jitter, and never puts query strings (which can hold API keys or
SAS signatures) into error messages. The transport is injectable, so every tool can be
tested against a fake Microsoft cloud without a network.
"""

from __future__ import annotations

import email.utils
import json
import random
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from cloud_checks import __version__

USER_AGENT = f"cloud-security-checks/{__version__} (+https://github.com/as70023333/cloud-security-checks)"
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class HttpError(Exception):
    """An HTTP call failed after retries. ``status`` is 0 for network errors."""

    def __init__(self, status: int, message: str, *, url: str = "", body: str = "") -> None:
        prefix = f"HTTP {status}" if status else "Network error"
        where = f" ({url})" if url else ""
        super().__init__(f"{prefix}: {message}{where}")
        self.status = status
        self.url = url
        self.body = body


class TransportError(Exception):
    """A network-level failure (DNS, TLS, timeout, connection reset)."""


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    timeout: float


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if not self.body.strip():
            return None
        return json.loads(self.body.decode("utf-8-sig"))


Transport = Callable[[Request], Response]


def urllib_transport(req: Request) -> Response:
    """Default transport. Honours HTTPS_PROXY / NO_PROXY and SSL_CERT_FILE like urllib does."""
    request = urllib.request.Request(req.url, data=req.body, method=req.method, headers=req.headers)
    try:
        with urllib.request.urlopen(request, timeout=req.timeout) as resp:  # noqa: S310 - URLs are built by the tools
            return Response(resp.status, resp.read(), dict(resp.headers.items()))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:  # pragma: no cover - defensive
            body = b""
        headers = dict(exc.headers.items()) if exc.headers else {}
        return Response(exc.code, body, headers)
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, ssl.SSLError) as exc:
        reason = getattr(exc, "reason", exc)
        raise TransportError(str(reason)) from exc


def redact_url(url: str) -> str:
    """Drop the query string and fragment: they can carry keys, tokens or SAS signatures."""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _error_message(resp: Response) -> str:
    try:
        data = resp.json()
    except (ValueError, UnicodeDecodeError):
        data = None
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            code = err.get("code") or ""
            msg = err.get("message") or ""
            return f"{code}: {msg}".strip(": ") or "request failed"
        for key in ("error_description", "message", "detail", "error", "query_status"):
            if isinstance(data.get(key), str) and data[key]:
                return data[key].splitlines()[0][:300]
    text = resp.text.strip()
    return text.splitlines()[0][:300] if text else "request failed"


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 20.0,
        retries: int = 3,
        backoff: float = 1.0,
        max_wait: float = 60.0,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        user_agent: str = USER_AGENT,
    ) -> None:
        if retries < 0:
            raise ValueError("retries must be >= 0")
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_wait = max_wait
        self.transport: Transport = transport or urllib_transport
        self._sleep = sleep
        self.user_agent = user_agent

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | Iterable[tuple[str, Any]] | None = None,
        json_body: Any = None,
        form: Mapping[str, Any] | None = None,
        body: bytes | None = None,
        ok: Iterable[int] = (200, 201, 202, 204),
        allow: Iterable[int] = (),
    ) -> Response:
        """Send a request. Statuses in ``ok`` or ``allow`` are returned; others raise HttpError."""
        if params:
            query = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}{'&' if '?' in url else '?'}{query}"
        hdrs = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        data: bytes | None = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif body is not None:
            data = body
        accepted = set(ok) | set(allow)
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self.transport(Request(method.upper(), url, dict(hdrs), data, self.timeout))
            except TransportError as exc:
                if attempt > self.retries:
                    raise HttpError(0, str(exc), url=redact_url(url)) from exc
                self._sleep(self._backoff(attempt))
                continue
            if resp.status in accepted:
                return resp
            if resp.status in RETRY_STATUSES and attempt <= self.retries:
                wait = self._retry_after(resp)
                self._sleep(wait if wait is not None else self._backoff(attempt))
                continue
            raise HttpError(resp.status, _error_message(resp), url=redact_url(url), body=resp.text[:2000])

    def _backoff(self, attempt: int) -> float:
        return min(self.max_wait, self.backoff * (2 ** (attempt - 1)) + random.uniform(0, 0.25))

    def _retry_after(self, resp: Response) -> float | None:
        value = resp.header("Retry-After")
        if not value:
            return None
        value = value.strip()
        try:
            seconds = float(value)
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return None
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            seconds = (when - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, min(self.max_wait, seconds))
