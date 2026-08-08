"""CLI entrypoint: python -m sentinelwatch"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from sentinelwatch.config import load_config, load_env
from sentinelwatch.pipeline import run


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinelwatch",
        description="Self-hosted vulnerability monitoring for shared hosting stacks",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=None,
        help="Path to config.yaml (default: config/config.yaml or $SENTINELWATCH_CONFIG)",
    )
    parser.add_argument(
        "--env",
        type=Path,
        default=None,
        help="Path to .env file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Debug logging",
    )
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)
    load_env(args.env)

    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        return 2

    stats = run(config)
    # Non-zero only if every collector failed and nothing was fetched
    if stats["collectors"] > 0 and stats["failures"] == stats["collectors"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
