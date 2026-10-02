"""Report writers: Markdown tables, CSV, JSON and a little terminal colour."""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

_COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
           "low": "\033[36m", "info": "\033[2m", "malicious": "\033[1;31m",
           "suspicious": "\033[33m", "harmless": "\033[32m", "unknown": "\033[2m"}
_RESET = "\033[0m"


def color_enabled(stream: Any = None, disabled: bool = False) -> bool:
    stream = stream or sys.stdout
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(label: str, text: str, enabled: bool) -> str:
    code = _COLORS.get(label.lower())
    return f"{code}{text}{_RESET}" if enabled and code else text


def md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(md_escape(h) for h in headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(md_escape(c) for c in row) + " |")
    return "\n".join(lines)


def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return str(obj)


def to_json(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=_json_default, ensure_ascii=False)


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        text = "; ".join(str(v) for v in value)  # checked below like any other text
    elif isinstance(value, dict):
        text = json.dumps(value, default=_json_default, ensure_ascii=False)
    else:
        text = str(value)
    # Neutralise spreadsheet formula injection: attacker-controlled names end up in these files.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _cell(row.get(k)) for k in fields})


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")


def parse_formats(value: str, allowed: Sequence[str]) -> list[str]:
    formats = [f.strip().lower() for f in value.split(",") if f.strip()]
    bad = [f for f in formats if f not in allowed]
    if bad:
        raise ValueError(f"unknown format(s) {', '.join(bad)}; choose from {', '.join(allowed)}")
    return formats
