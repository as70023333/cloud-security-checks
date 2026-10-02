"""Environment and .env handling (no third-party dependency)."""

from __future__ import annotations

import os
import re
from pathlib import Path

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def load_dotenv(path: str | os.PathLike[str] = ".env", *, override: bool = False) -> list[str]:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Existing environment variables win unless ``override`` is true, so a value set by the
    shell, a CI secret or a container platform is never silently replaced by a file.
    Returns the names that were set.
    """
    p = Path(path)
    if not p.is_file():
        return []
    loaded: list[str] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(line)
        if not match:
            continue
        key, value = match.groups()
        if len(value) >= 2 and value[0] in ("'", '"') and value.endswith(value[0]):
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if override or key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def env_str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else default


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


def env_list(name: str) -> list[str]:
    """Comma- or whitespace-separated list from an environment variable."""
    value = os.environ.get(name, "")
    return [item for item in re.split(r"[,\s]+", value) if item]
