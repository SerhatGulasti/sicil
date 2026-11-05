"""Command line entry point."""

import argparse
import os
import sqlite3
import sys

from . import rules
from .run import RunResult, execute
from .sources import Sources
from .store import Store

DEFAULT_DB = os.path.expanduser("~/.local/state/sicil/sicil.db")


def format_result(result: RunResult) -> str:
    status = lambda ok: "ok" if ok else "FAILED"
    count = lambda level: result.levels.get(level, 0)
    lines = [
        f"run {result.run_id}: repo {status(result.repo_ok)},"
        f" aur {status(result.aur_ok)}, yoklama {status(result.yoklama_ok)}",
        f"open: {count(rules.RED)} red, {count(rules.YELLOW)} yellow,"
        f" {count(rules.UNVERIFIED)} unverified,"
        f" {count(rules.NOT_FOUND)} not in AUR;"
        f" {result.removal_suggestions} removal suggestions",
    ]
    for title, rows in (
        ("new", result.diff.new),
        ("closed", result.diff.closed),
        ("level changed", result.diff.changed),
    ):
        if rows:
            lines.append(f"{title} ({len(rows)}):")
            lines.extend("  " + " ".join(str(part) for part in row) for row in rows)
    if result.warnings:
        lines.append("warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings)
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    try:
        store = Store(args.db)
        try:
            result = execute(store, Sources())
        finally:
            store.close()
    except (OSError, sqlite3.Error) as e:
        print(f"sicil: {args.db}: {e}", file=sys.stderr)
        return 1
    print(format_result(result))
    # A source being down is an expected state, reported as a warning.
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sicil")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser(
        "run", help="check the sources and record what changed"
    )
    run_parser.add_argument("--db", default=DEFAULT_DB, help="database path")
    run_parser.set_defaults(func=run)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
