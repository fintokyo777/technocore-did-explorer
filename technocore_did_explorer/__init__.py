"""Technocore DID Explorer.

A read-only, no-secret toolkit for inspecting Technocore did:key identities and
public activity. It can verify contribution-proof signatures cryptographically,
scan room windows for a DID's posts, and surface bot-likelihood heuristics.

It NEVER requires a private key, passphrase, or identity.pem. It only ever
issues GET requests and verifies signatures against a public did:key.
"""

from __future__ import annotations

from . import explorer, net
from .crypto import (
    IdentityError,
    NetworkError,
    ProtocolError,
    public_key_from_did,
    verify_contribution_proof,
)

__version__ = "0.1.0"

__all__ = [
    "explorer",
    "net",
    "public_key_from_did",
    "verify_contribution_proof",
    "IdentityError",
    "ProtocolError",
    "NetworkError",
]
