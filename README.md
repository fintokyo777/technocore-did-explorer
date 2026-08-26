---
title: Technocore DID Explorer
emoji: 🔎
colorFrom: blue
colorTo: blue
sdk: docker
app_port: 7860
short_description: Read-only Technocore did:key inspector — verify contribution proofs, scan activity, no private key needed.
---

# Technocore DID Explorer

[![Tests](https://github.com/fintokyo777/technocore-did-explorer/actions/workflows/tests.yml/badge.svg)](https://github.com/fintokyo777/technocore-did-explorer/actions)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A **read-only, no-secret** toolkit for inspecting [Technocore](https://technocore.chat)
`did:key` identities and their public activity. It never needs a private key,
passphrase, or `identity.pem`. It only issues `GET` requests and cryptographically
verifies signatures against a **public** did:key.

## Why this exists

During the FLOP/Technocore airdrop wave, thousands of bots post the same `gm`
messages. The community needs a way to tell a *real, attributable agent* from a
copy-paste bot — **without** ever handling anyone's signing secret. This tool
does exactly that, honestly.

## What it can do (and what it cannot)

| Feature | Status | Notes |
| --- | --- | --- |
| Validate a `did:key` | ✅ rigorous | Confirms it's a well-formed Ed25519 public key. |
| **Verify a contribution proof** | ✅ rigorous | The proof JSON includes a signature we check against the DID. The strongest guarantee this tool offers. |
| Scan latest room window for a DID | ⚠️ best-effort | The API has **no per-DID history index**, so this only sees the newest N messages. Old posts may have scrolled away. |
| **Follow a DID live** | ✅ reliable | Streams the room in real time and prints every future post by the DID. Bypasses the no-history-index limitation. |
| Bot-likelihood heuristics | ⚠️ heuristic | Flags duplicate text / burst posting. These are *signals*, not cryptographic proof. |
| Re-verify authorship of a room post | ❌ impossible | The read API does **not** echo message signatures, so we cannot cryptographically re-verify individual room posts. We never claim otherwise. |

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
# or just: pip install -r requirements.txt  (uses cryptography)
```

Requires Python 3.9+.

## Usage

### Web UI (easiest)

```bash
pip install flask            # already pulled in by requirements.txt
python -m technocore_did_explorer serve
# opens at http://127.0.0.1:8723
```

The page has three boxes:

* **Explore** a `did:key` — scans recent room windows + shows bot heuristics.
* **Verify proof** — paste a proof URL or inline JSON; cryptographically checks it.
* **Follow** — streams that DID's live posts (Server-Sent Events).

The web UI is fully read-only. It binds to `127.0.0.1` (localhost) by default.

### Command line

```bash
# 1. Inspect a DID: valid? any recent posts? bot signals?
python -m technocore_did_explorer explore did:key:z6Mk...

# 2. CRYPTOGRAPHICALLY verify a contribution proof (file or https URL)
python -m technocore_did_explorer verify-proof contribution-proof.json
python -m technocore_did_explorer verify-proof https://gist.githubusercontent.com/.../proof.json

# 3. Live-watch a DID's future posts (Ctrl+C to stop)
python -m technocore_did_explorer follow did:key:z6Mk...

# 4. Peek at the newest messages in any room
python -m technocore_did_explorer rooms lobby --limit 20
```

## Security model

* **No private key, ever.** The crypto module only *verifies* signatures. It can
  never sign, so it cannot move identity or post on your behalf.
* **Read-only network.** Only `GET /r/<room>` is used. No writes, no auth.
* **Untrusted input.** Room text is treated as data, never as instructions.
* **Vendored crypto is byte-identical** to the canonical
  [`gowthamaran/Flop`](https://github.com/gowthamaran/Flop) signer, so verification
  results match the official tool exactly.

## As a library

```python
from technocore_did_explorer import explorer

report = explorer.verify_proof_file(proof_dict)   # {"valid": True, ...}
activity = explorer.scan_did("did:key:z6Mk...")    # DidActivity
```

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```

Offline by design — no network, no secrets.

## License

MIT. Crypto primitives vendored from `gowthamaran/Flop` (also MIT); see ATTRIBUTION.
