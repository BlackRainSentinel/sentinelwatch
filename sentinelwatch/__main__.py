"""CLI entrypoint: python -m sentinelwatch [--schedule fast|slow]"""

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
    parser = argparse.ArgumentParser(prog="sentinelwatch")
    parser.add_argument("-c", "--config", type=Path, default=None)
    parser.add_argument("--env", type=Path, default=None)
    parser.add_argument(
        "--schedule",
        choices=["fast", "slow", "all"],
        default="all",
        help="Run only fast (Tier1/2) or slow (tier3) collectors",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)
    load_env(args.env)
    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        logging.error("%s", exc)
        return 2

    schedule = None if args.schedule == "all" else args.schedule
    stats = run(config, schedule=schedule)
    if stats["collectors"] > 0 and stats["failures"] == stats["collectors"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
