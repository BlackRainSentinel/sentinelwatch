"""Load YAML configuration and environment secrets."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


def load_env(env_path: Path | None = None) -> None:
    """Load .env from project root (or an explicit path)."""
    if env_path is not None:
        load_dotenv(env_path)
        return
    root = Path(__file__).resolve().parent.parent
    load_dotenv(root / ".env")


def load_config(path: Path | str | None = None) -> dict[str, Any]:
    """Parse the YAML config file and return a plain dict."""
    config_path = Path(path) if path else Path(
        os.environ.get("SENTINELWATCH_CONFIG", DEFAULT_CONFIG_PATH)
    )
    if not config_path.is_file():
        raise FileNotFoundError(f"Config not found: {config_path}")
    with config_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {config_path}")
    return data


def require_env(*names: str) -> dict[str, str]:
    """Return named environment variables; raise if any are missing/empty."""
    values: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        value = os.environ.get(name, "").strip()
        if not value:
            missing.append(name)
        else:
            values[name] = value
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")
    return values


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
