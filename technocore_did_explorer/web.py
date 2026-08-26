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
  :root {
    color-scheme: light dark;
    --bg: #f5f5f7;
    --card: #ffffff;
    --border: #e3e3e8;
    --text: #1d1d1f;
    --muted: #6e6e73;
    --accent: #0071e3;
    --accent-press: #005bbd;
    --ok: #1a8a3c;
    --bad: #c0341d;
    --code-bg: #1d1d1f;
    --code-fg: #34c759;
    --radius: 14px;
    --shadow: 0 1px 2px rgba(0,0,0,.04), 0 8px 24px rgba(0,0,0,.06);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #161617; --card: #232325; --border: #38383c;
      --text: #f5f5f7; --muted: #a1a1a6; --shadow: 0 1px 2px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.5);
    }
  }
  * { box-sizing: border-box; }
  body {
    font: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
    background: var(--bg); color: var(--text);
    max-width: 760px; margin: 0 auto; padding: 3rem 1.2rem 4rem;
    -webkit-font-smoothing: antialiased;
  }
  header { margin-bottom: 2rem; }
  h1 { font-size: 1.7rem; font-weight: 600; letter-spacing: -.02em; margin: 0 0 .4rem; }
  .sub { color: var(--muted); font-size: .95rem; margin: 0; }
  .banner {
    background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
    padding: .85rem 1rem; box-shadow: var(--shadow); color: var(--muted);
    font-size: .88rem; margin-bottom: 1.6rem;
  }
  .banner b { color: var(--text); font-weight: 600; }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1.4rem 1.5rem; box-shadow: var(--shadow); margin-bottom: 1.4rem;
  }
  .card h2 { font-size: 1.02rem; font-weight: 600; margin: 0 0 1rem; letter-spacing: -.01em; }
  label { display:block; font-size: .82rem; font-weight: 500; color: var(--muted); margin: .9rem 0 .35rem; }
  label:first-of-type { margin-top: 0; }
  input[type=text]{
    width:100%; padding:.7rem .85rem; font-size: .95rem; color: var(--text);
    background: var(--bg); border:1px solid var(--border); border-radius: 10px;
    transition: border-color .15s, box-shadow .15s; outline: none;
  }
  input[type=text]:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(0,113,227,.18); }
  .row { display:flex; gap:.6rem; flex-wrap: wrap; }
  button {
    margin-top: 1.1rem; padding:.6rem 1.2rem; font-size: .92rem; font-weight: 500;
    border:0; border-radius: 10px; background: var(--accent); color:#fff; cursor:pointer;
    transition: background .15s, transform .05s;
  }
  button:hover { background: var(--accent-press); }
  button:active { transform: scale(.98); }
  button.ghost { background: transparent; color: var(--bad); border: 1px solid var(--border); }
  button.ghost:hover { background: rgba(192,52,29,.08); }
  .status { font-size:.8rem; margin-top:.7rem; min-height: 1em; }
  .status.ok { color: var(--ok); } .status.bad { color: var(--bad); }
  pre {
    background: var(--code-bg); color: var(--code-fg); padding: 1rem 1.1rem; border-radius: 10px;
    overflow:auto; max-height: 440px; font: 12.5px/1.55 ui-monospace, "SF Mono", Menlo, monospace;
    white-space: pre-wrap; word-break: break-word; margin: 0;
  }
  #stream { max-height: 260px; }
  .divider { height:1px; background: var(--border); margin: 1.6rem 0; border:0; }
  footer { color: var(--muted); font-size:.8rem; text-align:center; margin-top: 2rem; }
</style></head>
<body>
<header>
  <h1>Technocore DID Explorer</h1>
  <p class="sub">Read-only identity &amp; proof inspector</p>
</header>

<div class="banner">
  No private key needed. It can <b>verify</b> contribution proofs cryptographically
  and scan public room activity &mdash; it can <b>never sign or post</b>.
</div>

<div class="card">
  <h2>Explore a DID</h2>
  <form id="exploreForm">
    <label>did:key</label>
    <input type="text" id="did" placeholder="did:key:z6Mk...">
    <label>Rooms (comma-separated)</label>
    <input type="text" id="rooms" value="lobby,technocore">
    <label>Window per room (recent messages scanned)</label>
    <input type="text" id="window" value="5000">
    <div class="row"><button type="submit">Explore</button></div>
    <div class="status" id="exploreStatus"></div>
  </form>
</div>

<div class="card">
  <h2>Verify a contribution proof</h2>
  <form id="verifyForm">
    <label>Proof URL or inline JSON</label>
    <input type="text" id="proof" placeholder="https://.../proof.json">
    <div class="row"><button type="submit">Verify proof</button></div>
    <div class="status" id="verifyStatus"></div>
  </form>
</div>

<div class="card">
  <h2>Follow a DID live</h2>
  <form id="followForm">
    <label>did:key</label>
    <input type="text" id="fdid" placeholder="did:key:z6Mk...">
    <label>Rooms (comma-separated)</label>
    <input type="text" id="frooms" value="lobby,technocore">
    <div class="row">
      <button type="submit">Start following</button>
      <button type="button" id="stopBtn" class="ghost">Stop</button>
    </div>
  </form>
  <pre id="stream">-- waiting for live posts --</pre>
</div>

<hr class="divider">
<h2 style="font-size:1.02rem;font-weight:600;margin:0 0 1rem">Results</h2>
<pre id="out">--</pre>

<footer>Technocore DID Explorer &middot; vendored crypto, no secrets</footer>

<script>
const out = document.getElementById('out');
function show(obj){ out.textContent = typeof obj==='string'?obj:JSON.stringify(obj,null,2); }
function status(id, msg, kind){ const el=document.getElementById(id); el.textContent=msg||''; el.className='status'+(kind?' '+kind:''); }

document.getElementById('exploreForm').onsubmit = async (e)=>{
  e.preventDefault();
  status('exploreStatus','');
  const did=document.getElementById('did').value.trim();
  const rooms=document.getElementById('rooms').value.trim();
  const window=document.getElementById('window').value.trim();
  if(!did){ status('exploreStatus','Enter a did:key', 'bad'); return; }
  const r=await fetch('/explore?did='+encodeURIComponent(did)+'&rooms='+encodeURIComponent(rooms)+'&window='+encodeURIComponent(window));
  const j=await r.json(); show(j);
  status('exploreStatus', j.error ? j.error : 'Done. '+(j.message_count||0)+' post(s) found.', j.error?'bad':'ok');
};
document.getElementById('verifyForm').onsubmit = async (e)=>{
  e.preventDefault();
  status('verifyStatus','');
  const proof=document.getElementById('proof').value.trim();
  if(!proof){ status('verifyStatus','Enter a proof URL or JSON', 'bad'); return; }
  const r=await fetch('/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proof})});
  const j=await r.json(); show(j);
  status('verifyStatus', j.valid ? '✓ Valid signature for '+j.did : ('✗ '+(j.error||'invalid')), j.valid?'ok':'bad');
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
document.getElementById('stopBtn').onclick=()=>{ if(es){ es.close(); es=null; } };
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
