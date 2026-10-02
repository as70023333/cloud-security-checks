"""Timestamp parsing for Microsoft APIs (7-digit fractions, trailing Z, missing zone)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_FRACTION = re.compile(r"\.(\d+)")


def parse_time(value: object) -> datetime | None:
    """Parse an ISO 8601 timestamp into an aware UTC datetime; None when empty or invalid."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("0001-01-01"):
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    # Python accepts at most 6 fractional digits; Microsoft APIs send up to 7.
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def days_between(later: datetime, earlier: datetime) -> int:
    return int((later - earlier).total_seconds() // 86400)
