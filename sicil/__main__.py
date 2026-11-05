"""Command line entry point."""

import argparse
import os
import sqlite3
import sys

from . import report as report_module
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
        f" aur {status(result.aur_ok)}, kernel {status(result.kernel_ok)},"
        f" yoklama {status(result.yoklama_ok)}",
        f"open: {count(rules.RED)} red, {count(rules.YELLOW)} yellow,"
        f" {count(rules.UNVERIFIED)} unverified,"
        f" {count(rules.LOOKS_CLOSED)} looks closed,"
        f" {count(rules.NOT_FOUND)} not in AUR,"
        f" {count(rules.INFO)} kernel notes;"
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
    if result.notified:
        lines.append(f"notified about {result.notified} new red findings")
    if result.warnings:
        lines.append("warnings:")
        lines.extend(f"  {warning}" for warning in result.warnings)
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    try:
        store = Store(args.db)
        try:
            state = os.path.dirname(os.path.abspath(args.db))
            result = execute(
                store, Sources(kernel_dir=os.path.join(state, "kernel-vulns"))
            )
        finally:
            store.close()
    except (OSError, sqlite3.Error) as e:
        print(f"sicil: {args.db}: {e}", file=sys.stderr)
        return 1
    print(format_result(result))
    # A source being down is an expected state, reported as a warning.
    return 0


def report(args: argparse.Namespace) -> int:
    try:
        loaded = report_module.load(args.db, all_findings=args.all)
    except report_module.ReportError as e:
        print(f"sicil: {e}", file=sys.stderr)
        return 1
    formatter = report_module.format_json if args.json else report_module.format_text
    try:
        print(formatter(loaded))
    except BrokenPipeError:
        # The reader closed the pipe, as `sicil report | head` does.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sicil")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser(
        "run", help="check the sources and record what changed"
    )
    run_parser.add_argument("--db", default=DEFAULT_DB, help="database path")
    run_parser.set_defaults(func=run)

    report_parser = commands.add_parser(
        "report", help="show the recorded findings, without touching the network"
    )
    report_parser.add_argument(
        "--all", action="store_true", help="include closed findings"
    )
    report_parser.add_argument("--json", action="store_true", help="print JSON")
    report_parser.add_argument("--db", default=DEFAULT_DB, help="database path")
    report_parser.set_defaults(func=report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
