"""DID activity scanning + heuristics (read-only, on public room data).

The Technocore read API does NOT echo message signatures, so we cannot
cryptographically re-verify authorship of individual room posts from the data
we receive -- the server already verified them at write time. What we CAN do
rigorously is:

  * confirm a did:key is well-formed (valid Ed25519 public key);
  * verify contribution-proof JSON cryptographically (that artifact includes a
    signature we can check against the DID);
  * scan a room window for posts attributed to a DID and verify each retained
    signature against room|nonce|text (technocore started keeping `sig` on
    2026-08-31; anything written before that is unverifiable forever);
  * surface heuristics that suggest bot-like behaviour (duplicate text, bursts).
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field
from typing import Any

from . import crypto

from . import net
from .crypto import (
    COMMIT_PATTERN,
    IdentityError,
    ProtocolError,
    public_key_from_did,
    verify_contribution_proof,
)


@dataclass
class MessageHit:
    seq: int
    ts: str
    text: str
    room: str
    author: str
    nonce: int | None
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "room": self.room,
            "from": self.author,
            "text": self.text,
            "nonce": self.nonce,
            "verified": self.verified,
        }


@dataclass
class DidActivity:
    did: str
    valid_did: bool
    rooms_scanned: list[str] = field(default_factory=list)
    messages: list[MessageHit] = field(default_factory=list)
    unique_texts: int = 0
    duplicate_text_ratio: float = 0.0
    first_seq: int | None = None
    last_seq: int | None = None
    spread_seconds: float | None = None
    possible_bot_signals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "did": self.did,
            "valid_did": self.valid_did,
            "rooms_scanned": self.rooms_scanned,
            "message_count": len(self.messages),
            "verified_count": sum(1 for m in self.messages if m.verified),
            "unverified_count": sum(1 for m in self.messages if not m.verified),
            "unique_texts": self.unique_texts,
            "duplicate_text_ratio": round(self.duplicate_text_ratio, 4),
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "spread_seconds": self.spread_seconds,
            "possible_bot_signals": self.possible_bot_signals,
            "notes": self.notes,
            "messages": [m.to_dict() for m in self.messages],
        }


def check_did(did: str) -> bool:
    """Return True iff the did:key is a well-formed Ed25519 public key."""
    try:
        public_key_from_did(did)
        return True
    except (ProtocolError, IdentityError):
        return False


def _ts_to_seconds(ts: str) -> float | None:
    try:
        # ISO-8601 with trailing Z
        return float(
            __import__("datetime").datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        )
    except Exception:
        return None


def scan_did(
    did: str,
    rooms: list[str] | None = None,
    *,
    window_per_room: int = 5000,
    limit: int = 200,
    base_url: str = net.DEFAULT_BASE_URL,
    timeout: float = net.DEFAULT_TIMEOUT_SECONDS,
) -> DidActivity:
    """Scan the newest messages of each room for posts attributed to ``did``.

    Hard limit, verified 2026-09-02: the API ignores ``since``/``before``/
    ``after``/``offset`` and always returns only the newest ~200 messages. There
    is no history access and no per-DID index, so this sees a live tail, not a
    searchable archive. ``window_per_room`` is accepted for compatibility but
    cannot widen that tail. Use ``follow`` to catch posts as they happen.
    """
    if rooms is None:
        rooms = ["lobby", "technocore"]

    activity = DidActivity(did=did, valid_did=check_did(did))
    if not activity.valid_did:
        activity.notes.append("did:key is not a valid Ed25519 public key; nothing to scan.")
        return activity

    for room in rooms:
        activity.rooms_scanned.append(room)
        try:
            resp = net.read_room(room, limit=limit, base_url=base_url, timeout=timeout)
        except (net.NetworkError, ProtocolError) as exc:
            activity.notes.append(f"room '{room}' read failed: {exc}")
            continue
        msgs = resp.get("messages", [])
        seen = len(msgs)
        if msgs:
            activity.notes.append(
                f"room '{room}': saw seq {msgs[0].get('seq')}..{msgs[-1].get('seq')} "
                f"({seen} messages; server returns only this tail)"
            )
        for m in msgs:
            if m.get("from") == did:
                activity.messages.append(
                    MessageHit(
                        seq=m.get("seq"),
                        ts=m.get("ts", ""),
                        text=m.get("text", ""),
                        room=room,
                        author=m.get("from", ""),
                        nonce=m.get("nonce"),
                        verified=crypto.verify_message(room, m),
                    )
                )

    _analyse(activity)
    return activity


def _analyse(activity: DidActivity) -> None:
    msgs = activity.messages
    if not msgs:
        activity.notes.append(
            "No posts found in the scanned windows. The DID may have posted "
            "outside the recent window, or may never have posted."
        )
        return
    texts = [m.text for m in msgs]
    counts = collections.Counter(texts)
    activity.unique_texts = len(counts)
    activity.duplicate_text_ratio = 1.0 - (len(counts) / len(msgs))
    seqs = [m.seq for m in msgs if isinstance(m.seq, int)]
    times = [_ts_to_seconds(m.ts) for m in msgs]
    times = [t for t in times if t is not None]
    if seqs:
        activity.first_seq = min(seqs)
        activity.last_seq = max(seqs)
    if len(times) >= 2:
        activity.spread_seconds = max(times) - min(times)

    # Heuristics -- explicitly labelled as signals, not proof.
    if activity.duplicate_text_ratio >= 0.5 and len(msgs) >= 4:
        activity.possible_bot_signals.append(
            f"{activity.duplicate_text_ratio:.0%} of scanned posts repeat the same text"
        )
    if len(msgs) >= 10 and activity.spread_seconds is not None and activity.spread_seconds < 60:
        activity.possible_bot_signals.append(
            f"{len(msgs)} posts within {activity.spread_seconds:.0f}s (possible burst)"
        )
    if all(len(t) <= 12 for t in texts):
        activity.possible_bot_signals.append("all scanned posts are very short (<=12 chars)")


def verify_proof_file(proof: dict[str, Any]) -> dict[str, Any]:
    """Cryptographically verify a contribution-proof dict. Returns a report."""
    if not isinstance(proof, dict):
        return {"valid": False, "error": "proof must be a JSON object"}
    try:
        verify_contribution_proof(proof)
    except (ProtocolError, IdentityError) as exc:
        return {"valid": False, "did": proof.get("did"), "error": str(exc)}
    return {
        "valid": True,
        "did": proof.get("did"),
        "artifact_url": proof.get("artifact_url"),
        "commit": proof.get("commit"),
    }


def follow_did(
    did: str,
    rooms: list[str] | None = None,
    *,
    wait: float = 10.0,
    base_url: str = net.DEFAULT_BASE_URL,
    timeout: float = net.DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """Yield every live message attributed to ``did`` as it arrives.

    Unlike :func:`scan_did` (which only sees a recent window), this streams the
    room in real time, so it reliably catches *future* posts by the DID even
    though the API has no per-DID history index. Returns a generator of
    :class:`MessageHit`.
    """
    if not check_did(did):
        raise ProtocolError(f"{did} is not a valid Ed25519 did:key")
    if rooms is None:
        rooms = ["lobby", "technocore"]

    for room in rooms:
        try:
            initial = net.read_room(room, limit=1, base_url=base_url, timeout=timeout)
        except (net.NetworkError, ProtocolError) as exc:
            yield {"error": f"room '{room}' read failed: {exc}"}
            continue
        cursor = initial.get("last_seq") or 0
        for resp in net.follow_room(room, since=cursor, wait=wait, base_url=base_url, timeout=timeout):
            for m in resp.get("messages", []):
                if m.get("from") == did:
                    yield MessageHit(
                        seq=m.get("seq"),
                        ts=m.get("ts", ""),
                        text=m.get("text", ""),
                        room=room,
                        author=m.get("from", ""),
                        nonce=m.get("nonce"),
                        verified=crypto.verify_message(room, m),
                    )
    return None  # unreachable; keeps mypy quiet


def normalize_proof_source(raw: str) -> dict[str, Any] | None:
    """Accept a JSON string, or a path/URL to a proof file. Returns dict or None."""
    raw = raw.strip()
    if raw.startswith("{") or raw.startswith("["):
        try:
            return __import__("json").loads(raw)
        except json.JSONDecodeError:
            return None
    # treat as path or URL
    try:
        if raw.startswith("http://") or raw.startswith("https://"):
            import urllib.request

            with urllib.request.urlopen(raw, timeout=20) as r:  # noqa: S310 (https enforced by caller)
                data = r.read().decode("utf-8")
        else:
            data = __import__("pathlib").Path(raw).read_text(encoding="utf-8")
        return __import__("json").loads(data)
    except Exception:
        return None
