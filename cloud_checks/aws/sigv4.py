"""AWS Signature Version 4, standard library only.

Verified in the test suite against the worked example in the AWS documentation and the
"get-vanilla" case of the official SigV4 test suite.
"""

from __future__ import annotations

import hashlib
import hmac
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class Credentials:
    access_key: str
    secret_key: str
    session_token: str = ""
    source: str = ""

    def __repr__(self) -> str:  # never print the secret
        return f"Credentials(access_key={self.access_key[:4]}..., source={self.source!r})"


def _quote(value: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(value, safe=safe)


def canonical_query(query: str) -> str:
    """Sort parameters by name then value, URI-encoding both (spaces become %20, never '+')."""
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        pairs.append((_quote(urllib.parse.unquote_plus(name)), _quote(urllib.parse.unquote_plus(value))))
    return "&".join(f"{name}={value}" for name, value in sorted(pairs))


def canonical_uri(path: str, service: str) -> str:
    """S3 uses the path as sent; every other service URI-encodes each segment a second time."""
    path = path or "/"
    if service == "s3":
        return path
    return "/".join(_quote(segment) for segment in path.split("/"))


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    return key


def sign(method: str, url: str, headers: Mapping[str, str], body: bytes, credentials: Credentials,
         region: str, service: str, now: datetime | None = None) -> dict[str, str]:
    """Return the headers to send: the given ones plus Host, X-Amz-Date and Authorization.

    ``headers`` are the headers to sign in addition to host and x-amz-date. For S3 the payload
    hash header is added because S3 requires it.
    """
    now = now or datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    parts = urllib.parse.urlsplit(url)
    payload_hash = hashlib.sha256(body or b"").hexdigest()

    to_sign = {name.lower(): " ".join(str(value).split()) for name, value in headers.items()}
    to_sign["host"] = parts.netloc
    to_sign["x-amz-date"] = amz_date
    if credentials.session_token:
        to_sign["x-amz-security-token"] = credentials.session_token
    if service == "s3":
        to_sign["x-amz-content-sha256"] = payload_hash

    signed_names = ";".join(sorted(to_sign))
    canonical_headers = "".join(f"{name}:{to_sign[name]}\n" for name in sorted(to_sign))
    canonical_request = "\n".join([
        method.upper(), canonical_uri(parts.path, service), canonical_query(parts.query),
        canonical_headers, signed_names, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([ALGORITHM, amz_date, scope,
                                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    signature = hmac.new(signing_key(credentials.secret_key, date, region, service),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    out = {name: value for name, value in headers.items()}
    out["Host"] = parts.netloc
    out["X-Amz-Date"] = amz_date
    if credentials.session_token:
        out["X-Amz-Security-Token"] = credentials.session_token
    if service == "s3":
        out["X-Amz-Content-Sha256"] = payload_hash
    out["Authorization"] = (f"{ALGORITHM} Credential={credentials.access_key}/{scope}, "
                            f"SignedHeaders={signed_names}, Signature={signature}")
    return out
