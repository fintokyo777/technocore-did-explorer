# Attribution

This project vendors cryptographic and protocol primitives from
[`gowthamaran/Flop`](https://github.com/gowthamaran/Flop) (MIT license).

Specifically, the following were copied **verbatim** so verification results are
byte-identical to the canonical Technocore signer:

* `technocore_did_explorer/crypto.py`
  - `base58btc_encode` / `base58btc_decode`
  - `public_key_from_did` / `verify_bytes` (Ed25519 did:key verification)
  - `contribution_payload` / `verify_contribution_proof`
  - constants (`MULTICODEC_ED25519`, `MULTIBASE_LENGTH`, `SIGNATURE_LENGTH`, …)
* `technocore_did_explorer/net.py`
  - the read-only `GET /r/<room>` request/response validation logic

No signing code, private-key handling, or `init`/`say` logic was copied. This
tool can only *verify*, never *sign*.

Upstream copyright is retained under the MIT license. See the upstream
`ATTRIBUTION.md` and `LICENSE` for the full chain of derived works
(`zunmax/technocore-did-starter`, `Nerevarine22/technocore`).

This project itself is released under the MIT license.
