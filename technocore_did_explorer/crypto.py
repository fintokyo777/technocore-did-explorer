"""Vendored Technocore crypto primitives (verbatim from gowthamaran/Flop).

Copied exactly, so verification results match the canonical signer byte-for-byte.
No private key handling lives here -- this module only *verifies* signatures
against a public did:key and contribution-proof JSON. It can never sign.

Upstream: https://github.com/gowthamaran/Flop  (MIT)
"""

from __future__ import annotations

import base64
import json
import math
import re
import unicodedata
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# --- constants (identical to upstream) -------------------------------------
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_LENGTH = 48
SIGNATURE_LENGTH = 86

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_ERROR_RESPONSE_BYTES = 16 * 1024


def validate_timeout(value: float) -> float:
    """Return a finite, positive timeout within the supported range."""
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= 60
    ):
        raise ProtocolError("timeout must be greater than zero and at most 60 seconds")
    return float(value)

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {c: i for i, c in enumerate(BASE58BTC_ALPHABET)}

INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(rf"[A-Za-z0-9_-]{{{SIGNATURE_LENGTH}}}")
COMMIT_PATTERN = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")


class IdentityError(ValueError):
    """The identity cannot be created, loaded, or verified."""


class ProtocolError(ValueError):
    """An input does not satisfy the published Technocore protocol."""


class NetworkError(RuntimeError):
    """A Technocore HTTP request failed or returned an invalid response."""


# --- base58btc (identical to upstream) -------------------------------------
def base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def base58btc_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = BASE58BTC_INDEX[character]
        except KeyError as error:
            raise ProtocolError(f"invalid base58btc character: {character!r}") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


# --- did:key parsing + signature verification ------------------------------
def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Parse a canonical Ed25519 did:key into a verification key."""
    prefix = "did:key:"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise ProtocolError("DID must start with 'did:key:z6Mk'")
    multibase = did[len(prefix):]
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ProtocolError("DID must be the canonical 48-character Ed25519 multibase form")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ProtocolError("DID must contain an ed25519-pub key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise ProtocolError("DID contains an invalid Ed25519 public key") from error


def verify_bytes(did: str, signature: str, payload: bytes) -> None:
    """Verify a base64url Ed25519 signature against a did:key."""
    if SIGNATURE_PATTERN.fullmatch(signature or "") is None:
        raise ProtocolError("signature must contain 86 unpadded base64url characters")
    raw_signature = base64.urlsafe_b64decode(signature + "==")
    try:
        public_key_from_did(did).verify(raw_signature, payload)
    except InvalidSignature as error:
        raise IdentityError("signature does not match the DID and payload") from error


# --- contribution-proof verification ---------------------------------------
def contribution_payload(artifact_url: str, commit: str) -> bytes:
    """Build a deterministic payload linking a DID to one published revision.

    Mirrors the canonical signer: require an absolute HTTPS URL with no fragment
    and no embedded credentials, plus a full 40/64-char hex commit. The exact
    payload bytes must match the signer or verification fails.
    """
    if not isinstance(artifact_url, str) or not isinstance(commit, str):
        raise ProtocolError("artifact URL and commit must be strings")
    if artifact_url != artifact_url.strip():
        raise ProtocolError("artifact URL must not contain surrounding whitespace")
    if not artifact_url.lower().startswith("https://") or "#" in artifact_url:
        raise ProtocolError("artifact URL must be an absolute HTTPS URL without a fragment")
    if "@" in artifact_url.split("://", 1)[-1].split("/", 1)[0]:
        raise ProtocolError("artifact URL must not contain embedded credentials")
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise ProtocolError("commit must be a complete 40- or 64-character hexadecimal revision")
    record = {
        "artifact_url": artifact_url,
        "commit": commit.lower(),
        "schema": "technocore-contribution-v1",
    }
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def verify_message(room: str, message: dict[str, Any]) -> bool:
    """True if the message's retained `sig` verifies against room|nonce|text."""
    sig = message.get("sig")
    if not isinstance(sig, str):
        return False
    payload = f"{room}|{message['nonce']}|{message['text']}".encode()
    try:
        verify_bytes(message["from"], sig, payload)
    except (IdentityError, ProtocolError, KeyError):
        return False
    return True


def verify_contribution_proof(proof: dict[str, Any]) -> None:
    """Validate a contribution proof's shape and Ed25519 signature."""
    if proof.get("schema") != "technocore-contribution-proof-v1":
        raise ProtocolError("unsupported contribution proof schema")
    required = ("did", "artifact_url", "commit", "signature")
    if any(not isinstance(proof.get(field), str) for field in required):
        raise ProtocolError("contribution proof is missing required string fields")
    payload = contribution_payload(proof["artifact_url"], proof["commit"])
    verify_bytes(proof["did"], proof["signature"], payload)
