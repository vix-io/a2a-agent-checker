"""a2a-check DOMAIN [DOMAIN ...] [--probe] [--json]
a2a-check --schema

Exit status: 0 if every domain passes or only warns, 1 if any fails,
2 for a usage error.
"""
from __future__ import annotations

import argparse
import json
import sys

from .check import check

def schema_text() -> str:
    from importlib.resources import files
    return files("a2a_agent_checker").joinpath("report.schema.json").read_text()


MARK = {"fail": "FAIL", "warn": "warn", "info": "info"}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="a2a-check",
                                description="Check a domain's A2A Agent Card against v1.0.")
    p.add_argument("targets", nargs="*", help="a domain (example.com) or a full card URL")
    p.add_argument("--probe", action="store_true",
                   help="also call GetTask for a random id on each JSONRPC endpoint (read-only)")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--schema", action="store_true",
                   help="print the JSON Schema of the --json output and exit")
    args = p.parse_args(argv)
    if args.schema:
        print(schema_text())
        return 0
    if not args.targets:
        p.error("give at least one domain or card URL")

    reports = [check(t, probe=args.probe) for t in args.targets]
    if args.json:
        print(json.dumps([r.as_dict() for r in reports], indent=2))
    else:
        for r in reports:
            name = (r.card or {}).get("name") if isinstance(r.card, dict) else None
            print(f"{r.domain}: {r.verdict.upper()}" + (f"  ({name})" if name else ""))
            print(f"  {r.card_url}")
            for f in r.findings:
                print(f"  {MARK[f.level]:4}  {f.message}")
            print()
    return 1 if any(r.verdict == "fail" for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
