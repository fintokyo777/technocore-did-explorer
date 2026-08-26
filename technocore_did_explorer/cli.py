#!/usr/bin/env python3
"""Command-line interface for the Technocore DID Explorer.

Usage examples
--------------
  # Inspect a DID: well-formed? any recent posts? bot signals?
  python -m technocore_did_explorer explore did:key:z6Mk...

  # Verify a contribution proof (JSON file or URL)
  python -m technocore_did_explorer verify-proof contribution-proof.json
  python -m technocore_did_explorer verify-proof https://gist.githubusercontent.com/.../proof.json

  # Peek at the newest messages in a room
  python -m technocore_did_explorer rooms lobby --limit 20

This tool is read-only and never needs a private key.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import explorer, net
from .crypto import IdentityError, NetworkError, ProtocolError


def _print_json(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def cmd_explore(args: argparse.Namespace) -> int:
    activity = explorer.scan_did(
        args.did,
        rooms=args.rooms.split(",") if args.rooms else None,
        window_per_room=args.window,
        limit=args.limit,
        base_url=args.base_url,
        timeout=args.timeout,
    )
    _print_json(activity.to_dict())
    return 0


def cmd_verify_proof(args: argparse.Namespace) -> int:
    proof = explorer.normalize_proof_source(args.proof)
    if proof is None:
        print(f"error: could not parse proof from '{args.proof}'", file=sys.stderr)
        return 1
    report = explorer.verify_proof_file(proof)
    _print_json(report)
    return 0 if report.get("valid") else 1


def cmd_rooms(args: argparse.Namespace) -> int:
    try:
        resp = net.read_room(
            args.room, limit=args.limit, base_url=args.base_url, timeout=args.timeout
        )
    except (NetworkError, ProtocolError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out = {
        "room": resp.get("room"),
        "count": resp.get("count"),
        "last_seq": resp.get("last_seq"),
        "messages": resp.get("messages", []),
    }
    _print_json(out)
    return 0


def cmd_follow(args: argparse.Namespace) -> int:
    import signal

    stop = {"go": True}

    def _handler(_sig, _frame):
        stop["go"] = False

    signal.signal(signal.SIGINT, _handler)
    try:
        for hit in explorer.follow_did(
            args.did,
            rooms=args.rooms.split(",") if args.rooms else None,
            wait=args.wait,
            base_url=args.base_url,
            timeout=args.timeout,
        ):
            if isinstance(hit, dict) and "error" in hit:
                print(f"error: {hit['error']}", file=sys.stderr)
                continue
            if not stop["go"]:
                break
            print(json.dumps(hit.to_dict(), ensure_ascii=False), flush=True)
    except (IdentityError, ProtocolError, NetworkError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m technocore_did_explorer",
        description="Read-only Technocore DID explorer (no private key needed).",
    )
    parser.add_argument("--version", action="version", version="technocore-did-explorer 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    ex = sub.add_parser("explore", help="scan rooms for a DID's public activity")
    ex.add_argument("did", help="a did:key:z6Mk... identifier")
    ex.add_argument("--rooms", help="comma-separated rooms (default: lobby,technocore)")
    ex.add_argument("--window", type=int, default=5000, help="messages scanned per room")
    ex.add_argument("--limit", type=int, default=200, help="page size per request")
    ex.add_argument("--base-url", default=net.DEFAULT_BASE_URL)
    ex.add_argument("--timeout", type=float, default=net.DEFAULT_TIMEOUT_SECONDS)
    ex.set_defaults(func=cmd_explore)

    vp = sub.add_parser("verify-proof", help="cryptographically verify a contribution proof")
    vp.add_argument("proof", help="path, https URL, or inline JSON of a proof")
    vp.set_defaults(func=cmd_verify_proof)

    rm = sub.add_parser("rooms", help="peek at the newest messages in a room")
    rm.add_argument("room")
    rm.add_argument("--limit", type=int, default=20)
    rm.add_argument("--base-url", default=net.DEFAULT_BASE_URL)
    rm.add_argument("--timeout", type=float, default=net.DEFAULT_TIMEOUT_SECONDS)
    rm.set_defaults(func=cmd_rooms)

    fw = sub.add_parser("follow", help="stream live posts by a DID (Ctrl+C to stop)")
    fw.add_argument("did", help="a did:key:z6Mk... identifier")
    fw.add_argument("--rooms", help="comma-separated rooms (default: lobby,technocore)")
    fw.add_argument("--wait", type=float, default=10.0, help="long-poll seconds per request")
    fw.add_argument("--base-url", default=net.DEFAULT_BASE_URL)
    fw.add_argument("--timeout", type=float, default=net.DEFAULT_TIMEOUT_SECONDS)
    fw.set_defaults(func=cmd_follow)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (IdentityError, ProtocolError, NetworkError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
