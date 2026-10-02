"""A minimal signed AWS client: Query (XML), JSON and S3 REST calls. Read-only use only."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Callable, Iterable, Iterator, Mapping

from cloud_checks.aws.sigv4 import Credentials, sign
from cloud_checks.core.http import HttpClient, HttpError, Response

GLOBAL_REGION = "us-east-1"
THROTTLE_CODES = frozenset({"Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException",
                            "SlowDown", "RequestThrottled"})
DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure",
                          "UnrecognizedClientException", "InvalidClientTokenId", "OptInRequired",
                          "AuthorizationError", "AccessDeniedFault"})
_CODE = re.compile(r"<Code>([^<]+)</Code>")
_MESSAGE = re.compile(r"<Message>([^<]*)</Message>")


class AwsError(Exception):
    def __init__(self, code: str, message: str, status: int = 0) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message
        self.status = status

    @property
    def denied(self) -> bool:
        return self.code in DENIED_CODES or self.status in (401, 403)


def parse_xml(body: bytes) -> ET.Element:
    """Parse an AWS XML response and drop namespaces so paths are plain element names."""
    root = ET.fromstring(body)
    for element in root.iter():
        if "}" in element.tag:
            element.tag = element.tag.split("}", 1)[1]
    return root


def txt(element: ET.Element | None, path: str, default: str = "") -> str:
    if element is None:
        return default
    value = element.findtext(path)
    return value.strip() if value is not None else default


def flag(element: ET.Element | None, path: str) -> bool | None:
    """'true'/'false' (any case) -> bool; missing -> None."""
    value = txt(element, path).lower()
    return {"true": True, "false": False}.get(value)


def error_from(status: int, body: str) -> AwsError:
    code = message = ""
    stripped = body.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = {}
        code = str(data.get("__type") or data.get("code") or data.get("Code") or "").split("#")[-1]
        message = str(data.get("message") or data.get("Message") or "")
    else:
        found = _CODE.search(body)
        code = found.group(1) if found else ""
        found = _MESSAGE.search(body)
        message = found.group(1) if found else ""
    return AwsError(code or f"HTTP{status}", message.strip()[:300], status)


class AwsClient:
    def __init__(self, http: HttpClient, credentials: Credentials, *, now: Callable[[], datetime] | None = None,
                 sleep: Callable[[float], None] = time.sleep, throttle_retries: int = 4) -> None:
        self.http = http
        self.credentials = credentials
        self._now = now
        self.sleep = sleep
        self.throttle_retries = throttle_retries

    def request(self, method: str, url: str, *, service: str, region: str,
                headers: Mapping[str, str] | None = None, body: bytes = b"",
                allow: Iterable[int] = ()) -> Response:
        """Sign and send. Statuses in ``allow`` are returned; other errors raise AwsError."""
        allowed = tuple(allow)
        attempt = 0
        while True:
            attempt += 1
            signed = sign(method, url, headers or {}, body, self.credentials, region, service,
                          self._now() if self._now else None)
            # Query-protocol services answer in JSON when asked for it; keep their native format.
            signed.setdefault("Accept", "*/*")
            try:
                return self.http.request(method, url, headers=signed, body=body or None, ok=(200,), allow=allowed)
            except HttpError as exc:
                if exc.status == 0:
                    raise AwsError("NetworkError", str(exc)) from exc
                error = error_from(exc.status, exc.body)
                if error.code in THROTTLE_CODES and attempt <= self.throttle_retries:
                    self.sleep(min(20.0, 0.5 * (2 ** attempt)))
                    continue
                raise error from exc

    # --- Query protocol (IAM, STS, EC2, RDS): form-encoded POST, XML response ------------------
    def query(self, service: str, region: str, action: str, version: str,
              params: Mapping[str, Any] | None = None, *, host: str = "") -> ET.Element:
        form = {"Action": action, "Version": version}
        form.update({k: str(v) for k, v in (params or {}).items()})
        body = urllib.parse.urlencode(sorted(form.items())).encode("utf-8")
        url = f"https://{host or f'{service}.{region}.amazonaws.com'}/"
        resp = self.request("POST", url, service=service, region=region, body=body,
                            headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
        return parse_xml(resp.body)

    def query_pages(self, service: str, region: str, action: str, version: str, params: Mapping[str, Any] | None,
                    token_path: str, token_param: str, *, host: str = "", max_pages: int = 200) -> Iterator[ET.Element]:
        """Yield every page of a paginated Query API."""
        query = dict(params or {})
        for _ in range(max_pages):
            root = self.query(service, region, action, version, query, host=host)
            yield root
            token = txt(root, token_path)
            if not token:
                return
            query[token_param] = token

    # --- JSON protocols ------------------------------------------------------------------------
    def json_rpc(self, service: str, region: str, target: str, payload: Mapping[str, Any] | None = None) -> dict:
        body = json.dumps(payload or {}).encode("utf-8")
        resp = self.request("POST", f"https://{service}.{region}.amazonaws.com/", service=service, region=region,
                            body=body, headers={"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": target})
        return resp.json() or {}

    def rest_json(self, service: str, region: str, path: str) -> dict:
        resp = self.request("GET", f"https://{service}.{region}.amazonaws.com{path}", service=service, region=region)
        return resp.json() or {}

    # --- S3 ------------------------------------------------------------------------------------
    def s3(self, method: str, region: str, path: str, *, host: str = "", headers: Mapping[str, str] | None = None,
           allow: Iterable[int] = ()) -> Response:
        """Path-style S3 request (works for bucket names containing dots)."""
        endpoint = host or ("s3.amazonaws.com" if region == GLOBAL_REGION else f"s3.{region}.amazonaws.com")
        return self.request(method, f"https://{endpoint}{path}", service="s3", region=region, headers=headers,
                            allow=allow)
