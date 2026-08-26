"""Lightweight read-only web UI for the Technocore DID Explorer.

A single-page Flask app. It never handles a private key, never signs, and never
posts -- it only calls the read-only explorer functions and renders their JSON.
Input (a did:key or a proof URL/path) is validated before use.
"""

from __future__ import annotations

import json

from flask import Flask, Response, request, stream_with_context

from . import explorer, net
from .crypto import IdentityError, NetworkError, ProtocolError

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Technocore DID Explorer</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  .note { background: #ffd; color:#222; border:1px solid #cc0; padding:.6rem .8rem; border-radius:6px; }
  .card { border:1px solid #ccc; border-radius:8px; padding:1rem; margin:1rem 0; }
  label { display:block; font-weight:600; margin:.6rem 0 .2rem; }
  input[type=text]{ width:100%; padding:.5rem; box-sizing:border-box; border:1px solid #999; border-radius:6px; }
  button { margin-top:.7rem; padding:.5rem 1rem; border:0; border-radius:6px; background:#222; color:#fff; cursor:pointer; }
  pre { background:#111; color:#0f0; padding:.8rem; border-radius:6px; overflow:auto; max-height:420px; }
  .ok { color:#0a0; } .bad { color:#c00; }
  table { border-collapse:collapse; width:100%; }
  td,th { border:1px solid #ddd; padding:.3rem .5rem; text-align:left; font-size:.85rem; }
</style></head>
<body>
<h1>Technocore DID Explorer</h1>
<p class="note">Read-only. No private key needed. It can <b>verify</b> contribution proofs
cryptographically and scan public room activity -- it can never sign or post.</p>

<div class="card">
  <form id="exploreForm">
    <label>did:key to explore</label>
    <input type="text" id="did" placeholder="did:key:z6Mk...">
    <label>Rooms (comma-separated)</label>
    <input type="text" id="rooms" value="lobby,technocore">
    <label>Window per room (recent messages scanned)</label>
    <input type="text" id="window" value="5000">
    <button type="submit">Explore</button>
  </form>
</div>

<div class="card">
  <form id="verifyForm">
    <label>Contribution proof (URL or inline JSON)</label>
    <input type="text" id="proof" placeholder="https://.../proof.json">
    <button type="submit">Verify proof</button>
  </form>
</div>

<div class="card">
  <form id="followForm">
    <label>Follow a DID live (streams new posts)</label>
    <input type="text" id="fdid" placeholder="did:key:z6Mk...">
    <input type="text" id="frooms" value="lobby,technocore" style="margin-top:.4rem">
    <button type="submit">Start following</button>
    <button type="button" id="stopBtn" style="background:#933">Stop</button>
  </form>
  <pre id="stream"></pre>
</div>

<h3>Results</h3>
<pre id="out">--</pre>

<script>
const out = document.getElementById('out');
function show(obj){ out.textContent = typeof obj==='string'?obj:JSON.stringify(obj,null,2); }

document.getElementById('exploreForm').onsubmit = async (e)=>{
  e.preventDefault();
  const did=document.getElementById('did').value.trim();
  const rooms=document.getElementById('rooms').value.trim();
  const window=document.getElementById('window').value.trim();
  const r=await fetch('/explore?did='+encodeURIComponent(did)+'&rooms='+encodeURIComponent(rooms)+'&window='+encodeURIComponent(window));
  show(await r.json());
};
document.getElementById('verifyForm').onsubmit = async (e)=>{
  e.preventDefault();
  const proof=document.getElementById('proof').value.trim();
  const r=await fetch('/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proof})});
  show(await r.json());
};

let es=null;
document.getElementById('followForm').onsubmit = (e)=>{
  e.preventDefault();
  const did=document.getElementById('fdid').value.trim();
  const rooms=document.getElementById('frooms').value.trim();
  const box=document.getElementById('stream');
  box.textContent='';
  if(es) es.close();
  es=new EventSource('/follow?did='+encodeURIComponent(did)+'&rooms='+encodeURIComponent(rooms));
  es.onmessage=(ev)=>{ box.textContent += ev.data + '\\n'; box.scrollTop=box.scrollHeight; };
  es.onerror=()=>{ box.textContent += '[stream ended]\\n'; es.close(); };
};
document.getElementById('stopBtn').onclick=()=>{ if(es) es.close(); };
</script>
</body></html>"""


@app.route("/")
def index() -> str:
    return PAGE


@app.route("/explore")
def explore() -> Response:
    did = request.args.get("did", "").strip()
    rooms = request.args.get("rooms")
    try:
        window = int(request.args.get("window", "5000"))
    except ValueError:
        window = 5000
    if not explorer.check_did(did):
        return _json({"error": "not a valid did:key", "did": did}, 400)
    try:
        activity = explorer.scan_did(
            did,
            rooms=rooms.split(",") if rooms else None,
            window_per_room=window,
        )
    except (NetworkError, ProtocolError) as exc:
        return _json({"error": str(exc), "did": did}, 502)
    return _json(activity.to_dict())


@app.route("/verify", methods=["POST"])
def verify() -> Response:
    data = request.get_json(silent=True) or {}
    proof_src = (data.get("proof") or "").strip()
    if not proof_src:
        return _json({"error": "missing 'proof'"}, 400)
    proof = explorer.normalize_proof_source(proof_src)
    if proof is None:
        return _json({"error": "could not parse proof from input", "valid": False}, 400)
    report = explorer.verify_proof_file(proof)
    return _json(report, 200 if report.get("valid") else 422)


@app.route("/follow")
def follow() -> Response:
    did = request.args.get("did", "").strip()
    rooms = request.args.get("rooms")
    if not explorer.check_did(did):
        return _json({"error": "not a valid did:key"}, 400)

    def event_stream():
        try:
            for hit in explorer.follow_did(
                did, rooms=rooms.split(",") if rooms else None
            ):
                if isinstance(hit, dict) and "error" in hit:
                    yield f"data: {json.dumps(hit)}\n\n"
                    continue
                yield f"data: {json.dumps(hit.to_dict(), ensure_ascii=False)}\n\n"
        except (NetworkError, ProtocolError, IdentityError) as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _json(obj, status: int = 200) -> Response:
    return Response(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
        status=status,
        mimetype="application/json",
    )


def main() -> None:
    app.run(host="127.0.0.1", port=8723, debug=False)


if __name__ == "__main__":
    main()
