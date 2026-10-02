"""A fake HTTP transport: routes requests to handlers so tests never touch the network."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Callable

from cloud_checks.core.http import HttpClient, Request, Response, TransportError

Handler = Callable[[Request], Response]


def json_response(data: Any, status: int = 200, headers: dict | None = None) -> Response:
    return Response(status, json.dumps(data).encode("utf-8"), {"Content-Type": "application/json", **(headers or {})})


class FakeTransport:
    """Register (method, url-regex) -> handler or static response. Unmatched requests fail loudly."""

    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], Any]] = []
        self.calls: list[Request] = []

    def add(self, method: str, pattern: str, response: Any) -> "FakeTransport":
        self.routes.append((method.upper(), re.compile(pattern), response))
        return self

    def __call__(self, req: Request) -> Response:
        self.calls.append(req)
        for method, pattern, response in self.routes:
            if method == req.method and pattern.search(req.url):
                if callable(response):
                    return response(req)
                if isinstance(response, list):  # a queue of responses, last one repeats
                    item = response.pop(0) if len(response) > 1 else response[0]
                    if isinstance(item, Exception):
                        raise item
                    return item
                return response
        raise AssertionError(f"unexpected request {req.method} {req.url}")

    def client(self, **kwargs: Any) -> HttpClient:
        kwargs.setdefault("sleep", lambda _s: None)
        return HttpClient(transport=self, **kwargs)

    def requests_to(self, pattern: str) -> list[Request]:
        rx = re.compile(pattern)
        return [c for c in self.calls if rx.search(c.url)]


def query_params(req: Request) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(req.url).query))


def body_json(req: Request) -> Any:
    return json.loads(req.body.decode("utf-8")) if req.body else None


def body_form(req: Request) -> dict[str, str]:
    return dict(urllib.parse.parse_qsl(req.body.decode("utf-8"))) if req.body else {}


class StaticCredential:
    def __init__(self, token: str = "test-token") -> None:
        self.token = token
        self.scopes: list[str] = []

    def get_token(self, scope: str) -> str:
        self.scopes.append(scope)
        return self.token


NETWORK_DOWN = TransportError("connection reset")
