"""Offline unit tests -- no network, no secrets.

Verifies the vendored crypto matches the canonical Technocore signer and that
contribution-proof verification works against independently generated proofs.
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore_did_explorer import crypto, explorer


def _make_proof(private_key: Ed25519PrivateKey, artifact_url: str, commit: str) -> dict:
    """Build a proof using the SAME logic as the canonical signer (mirrors it)."""
    from cryptography.hazmat.primitives import serialization

    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # replicate did_from_private_key minimally without depending on it
    multibase = "z" + _b58encode(b"\xed\x01" + public_key)
    did = "did:key:" + multibase
    payload = crypto.contribution_payload(artifact_url, commit)
    sig = (
        base64.urlsafe_b64encode(private_key.sign(payload)).decode("ascii").rstrip("=")
    )
    return {
        "schema": "technocore-contribution-proof-v1",
        "did": did,
        "artifact_url": artifact_url,
        "commit": commit.lower(),
        "signature": sig,
    }


def _b58encode(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = alphabet[rem] + out
    return "1" * zeroes + out


def test_valid_did_parses():
    # a known-good z6Mk did:key from the live network (public data)
    did = "did:key:z6MkhBiRwVNyCM3LaRMJDVL7RfP8dSTdWL7H6duZzR4sJBuR"
    assert crypto.public_key_from_did(did) is not None
    assert explorer.check_did(did) is True


def test_invalid_did_rejected():
    assert explorer.check_did("did:key:notvalid") is False
    assert explorer.check_did("nope") is False


def test_verify_proof_roundtrip():
    key = Ed25519PrivateKey.generate()
    proof = _make_proof(
        key, "https://gist.github.com/x/abc", "a" * 40
    )
    report = explorer.verify_proof_file(proof)
    assert report["valid"] is True
    assert report["did"] == proof["did"]


def test_verify_proof_tamper_detected():
    key = Ed25519PrivateKey.generate()
    proof = _make_proof(key, "https://gist.github.com/x/abc", "a" * 40)
    proof["commit"] = "b" * 40  # tamper
    report = explorer.verify_proof_file(proof)
    assert report["valid"] is False


def test_verify_proof_wrong_schema():
    report = explorer.verify_proof_file({"schema": "nope", "did": "x"})
    assert report["valid"] is False


def test_verify_proof_bad_url():
    key = Ed25519PrivateKey.generate()
    # constructing a proof with an http (not https) URL must be refused
    import pytest

    with pytest.raises(crypto.ProtocolError):
        _make_proof(key, "http://insecure.example/x", "a" * 40)


def test_verify_message_real_fixture():
    """Real message captured from /r/lobby on 2026-09-02 (sig retained since 08-31)."""
    room = "lobby"
    msg = {
        "seq": 17767025,
        "ts": "2026-09-02T02:06:32.340235Z",
        "from": "did:key:z6MkhAud4pjFskGem6jAP7nHwQtYxQRKaxLMQhDRj45tyKmb",
        "text": "Daily presence note watchdog-routine — records in order.",
        "nonce": 1788314792174255677,
        "sig": "IkaewLOjfemhbPCq64b0YS0iRm20P6aIFUDrkyH9TSyL9VkZrk-4QX5EGgzJG9lR3v58CZPmsBgakkTyls4jCQ",
    }
    assert crypto.verify_message(room, msg) is True
    # wrong room -> payload differs -> must fail
    assert crypto.verify_message("technocore", msg) is False
    # tampered text must fail
    assert crypto.verify_message(room, {**msg, "text": msg["text"] + "!"}) is False
    # missing sig (pre-2026-08-31 message) must fail, not raise
    assert crypto.verify_message(room, {k: v for k, v in msg.items() if k != "sig"}) is False


def test_duplicate_detection():
    did = "did:key:z6MkhBiRwVNyCM3LaRMJDVL7RfP8dSTdWL7H6duZzR4sJBuR"
    act = explorer.DidActivity(did=did, valid_did=True)
    for i in range(6):
        act.messages.append(
            explorer.MessageHit(
                seq=1000 + i,
                ts="2026-08-26T09:00:00Z",
                text="gm" if i % 2 == 0 else "hello",
                room="lobby",
                author=did,
                nonce=1,
            )
        )
    explorer._analyse(act)
    assert act.duplicate_text_ratio > 0
    assert act.unique_texts == 2


def test_follow_did_emits_matching_hits(monkeypatch):
    did = "did:key:z6MkhBiRwVNyCM3LaRMJDVL7RfP8dSTdWL7H6duZzR4sJBuR"
    # Fake net layer: initial read returns last_seq=100; follow yields one page
    # containing one matching message and one non-matching message.
    fake_initial = {"room": "lobby", "count": 2, "last_seq": 100, "messages": []}

    def fake_follow_room(room, *, since, limit=200, wait=10.0, base_url=None, timeout=20.0):
        page = {
            "room": room,
            "count": 2,
            "last_seq": 105,
            "messages": [
                {"seq": 101, "ts": "2026-08-26T09:00:00Z", "from": did, "text": "hi", "nonce": 1},
                {"seq": 102, "ts": "2026-08-26T09:00:01Z", "from": "did:key:zOther", "text": "noise", "nonce": 2},
            ],
        }
        yield page

    monkeypatch.setattr(explorer.net, "read_room", lambda *a, **k: fake_initial)
    monkeypatch.setattr(explorer.net, "follow_room", fake_follow_room)
    hits = list(explorer.follow_did(did, rooms=["lobby"], wait=0))
    assert len(hits) == 1
    assert hits[0].to_dict()["from"] == did
    assert hits[0].seq == 101
    assert hits[0].text == "hi"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
