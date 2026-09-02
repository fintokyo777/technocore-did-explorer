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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: light dark;
    --bg: #fafafa;
    --card: #ffffff;
    --border: #ececef;
    --text: #18181b;
    --muted: #71717a;
    --faint: #a1a1aa;
    --accent: #0a84ff;
    --accent-soft: #e8f1ff;
    --ok: #16a34a;
    --ok-soft: #ecfdf5;
    --bad: #dc2626;
    --bad-soft: #fef2f2;
    --radius: 16px;
    --shadow: 0 1px 2px rgba(24,24,27,.04), 0 8px 30px rgba(24,24,27,.06);
    --sans: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    --mono: "JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#0b0b0f; --card:#16161c; --border:#26262e; --text:#fafafa;
      --muted:#a1a1aa; --faint:#71717a; --accent:#409cff; --accent-soft:#0a2a4d;
      --ok:#4ade80; --ok-soft:#052e16; --bad:#f87171; --bad-soft:#450a0a;
      --shadow: 0 1px 2px rgba(0,0,0,.5), 0 8px 30px rgba(0,0,0,.5);
    }
  }
  * { box-sizing: border-box; }
  body {
    font-family: var(--sans); background: var(--bg); color: var(--text);
    max-width: 680px; margin: 0 auto; padding: 3.2rem 1.2rem 5rem;
    -webkit-font-smoothing: antialiased; line-height: 1.5;
  }
  .brand { display:flex; align-items:center; gap:.7rem; margin-bottom:2.4rem; }
  .logo {
    width:38px; height:38px; border-radius:11px; flex:0 0 auto;
    background: linear-gradient(135deg, var(--accent), #0a4dff);
    display:grid; place-items:center; color:#fff; font-weight:700; font-size:1.1rem;
    box-shadow: var(--shadow);
  }
  .brand h1 { font-size:1.35rem; font-weight:600; letter-spacing:-.02em; margin:0; }
  .brand p { margin:0; color:var(--muted); font-size:.85rem; }
  .card {
    background: var(--card); border:1px solid var(--border); border-radius: var(--radius);
    padding: 1.5rem 1.6rem; box-shadow: var(--shadow); margin-bottom: 1.3rem;
  }
  .card h2 { font-size:1.02rem; font-weight:600; margin:0 0 1.1rem; letter-spacing:-.01em; }
  .card .hint { color:var(--faint); font-size:.8rem; margin:-.7rem 0 1rem; }
  label { display:block; font-size:.78rem; font-weight:500; color:var(--muted); margin:.9rem 0 .4rem; letter-spacing:.01em; }
  label:first-of-type { margin-top:0; }
  input[type=text]{
    width:100%; padding:.75rem .9rem; font-size:.92rem; font-family:var(--sans); color:var(--text);
    background: var(--bg); border:1px solid var(--border); border-radius:11px; outline:none;
    transition: border-color .15s, box-shadow .15s;
  }
  input[type=text]:focus { border-color: var(--accent); box-shadow:0 0 0 3px var(--accent-soft); }
  input::placeholder { color: var(--faint); }
  .actions { display:flex; gap:.6rem; align-items:center; margin-top:1.1rem; }
  button {
    padding:.62rem 1.25rem; font-size:.9rem; font-weight:500; font-family:var(--sans);
    border:0; border-radius:11px; background:var(--accent); color:#fff; cursor:pointer;
    transition: filter .15s, transform .05s;
  }
  button:hover { filter: brightness(1.07); }
  button:active { transform: scale(.98); }
  button.ghost { background:transparent; color:var(--bad); border:1px solid var(--border); }
  button.ghost:hover { background: var(--bad-soft); }
  button:disabled { opacity:.5; cursor:default; }
  .spinner {
    width:14px; height:14px; border:2px solid rgba(255,255,255,.4); border-top-color:#fff;
    border-radius:50%; animation: spin .7s linear infinite; display:none;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* status pills + results */
  .pill { display:inline-flex; align-items:center; gap:.4rem; font-size:.8rem; font-weight:600;
    padding:.3rem .7rem; border-radius:999px; }
  .pill.ok { background:var(--ok-soft); color:var(--ok); }
  .pill.bad { background:var(--bad-soft); color:var(--bad); }
  .pill.muted { background:var(--bg); color:var(--muted); border:1px solid var(--border); }
  .result { margin-top:1.2rem; }
  .verdict { display:flex; align-items:center; gap:.8rem; padding:1rem 1.1rem; border-radius:12px; margin-bottom:1rem; }
  .verdict.ok { background:var(--ok-soft); }
  .verdict.bad { background:var(--bad-soft); }
  .verdict .mark { font-size:1.5rem; line-height:1; }
  .verdict .vt { font-weight:600; font-size:1rem; }
  .verdict .vs { font-size:.8rem; color:var(--muted); }
  .kv { display:grid; grid-template-columns: 120px 1fr; gap:.5rem .8rem; font-size:.86rem; margin-top:.4rem; }
  .kv dt { color:var(--muted); }
  .kv dd { margin:0; font-family:var(--mono); font-size:.8rem; word-break:break-all; }
  .stats { display:grid; grid-template-columns: repeat(3,1fr); gap:.7rem; margin:.3rem 0 1rem; }
  .stat { background:var(--bg); border:1px solid var(--border); border-radius:12px; padding:.8rem; text-align:center; }
  .stat .n { font-size:1.35rem; font-weight:600; letter-spacing:-.02em; }
  .stat .l { font-size:.7rem; color:var(--muted); margin-top:.2rem; }
  .chips { display:flex; flex-wrap:wrap; gap:.4rem; margin-top:.5rem; }
  .chip { font-size:.74rem; padding:.25rem .6rem; border-radius:999px; background:var(--bad-soft); color:var(--bad); }
  .chip.ok { background:var(--ok-soft); color:var(--ok); }
  details { margin-top:1rem; border-top:1px solid var(--border); padding-top:.8rem; }
  summary { cursor:pointer; font-size:.78rem; color:var(--muted); }
  pre { background:#0b0b0f; color:#d4d4d8; padding:1rem; border-radius:10px; overflow:auto;
    max-height:340px; font-family:var(--mono); font-size:12px; line-height:1.5; margin:.6rem 0 0; white-space:pre-wrap; word-break:break-word; }
  #stream { background:#0b0b0f; color:#a5b4fc; font-family:var(--mono); font-size:12px; padding:1rem;
    border-radius:12px; max-height:240px; overflow:auto; margin-top:1rem; white-space:pre-wrap; word-break:break-word; }
  footer { text-align:center; color:var(--faint); font-size:.76rem; margin-top:2.4rem; }
  a { color:var(--accent); text-decoration:none; }
</style></head>
<body>
<div class="brand">
  <div class="logo">◎</div>
  <div>
    <h1>Technocore DID Explorer</h1>
    <p>Read-only identity &amp; proof inspector</p>
  </div>
</div>

<div class="card">
  <h2>Verify a contribution proof</h2>
  <p class="hint">Paste a proof URL or the raw JSON. We check the signature against the DID — no key needed.</p>
  <form id="verifyForm">
    <label>Proof URL or inline JSON</label>
    <input type="text" id="proof" placeholder="https://gist.github.com/.../proof.json">
    <div class="actions">
      <button type="submit" id="verifyBtn">Verify proof</button>
      <div class="spinner" id="verifySpin"></div>
    </div>
  </form>
  <div class="result" id="verifyResult"></div>
</div>

<div class="card">
  <h2>Explore a DID</h2>
  <p class="hint">See recent activity and bot-likelihood signals. (Scans the latest room window only.)</p>
  <form id="exploreForm">
    <label>did:key</label>
    <input type="text" id="did" placeholder="did:key:z6Mk...">
    <label>Rooms (comma-separated)</label>
    <input type="text" id="rooms" value="lobby,technocore">
    <label>Window per room (recent messages scanned)</label>
    <input type="text" id="window" value="5000">
    <div class="actions">
      <button type="submit" id="exploreBtn">Explore</button>
      <div class="spinner" id="exploreSpin"></div>
    </div>
  </form>
  <div class="result" id="exploreResult"></div>
</div>

<div class="card">
  <h2>Follow a DID live</h2>
  <p class="hint">Streams that DID's new posts in real time.</p>
  <form id="followForm">
    <label>did:key</label>
    <input type="text" id="fdid" placeholder="did:key:z6Mk...">
    <label>Rooms (comma-separated)</label>
    <input type="text" id="frooms" value="lobby,technocore">
    <div class="actions">
      <button type="submit" id="followBtn">Start following</button>
      <button type="button" id="stopBtn" class="ghost" style="display:none">Stop</button>
    </div>
  </form>
  <pre id="stream" style="display:none"></pre>
</div>

<footer>Technocore DID Explorer &middot; vendored crypto, no secrets &middot; <a href="https://github.com/fintokyo777/technocore-did-explorer">GitHub</a></footer>

<script>
const esc = (s)=> String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const short = (s,n=42)=> s && s.length>n ? s.slice(0,n)+'…' : s;

function spin(id, on){ document.getElementById(id).style.display = on?'block':'none'; }

document.getElementById('verifyForm').onsubmit = async (e)=>{
  e.preventDefault();
  const box=document.getElementById('verifyResult');
  const proof=document.getElementById('proof').value.trim();
  if(!proof){ box.innerHTML='<span class="pill bad">Enter a proof URL or JSON</span>'; return; }
  spin('verifySpin',true);
  try {
    const r=await fetch('/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proof})});
    const j=await r.json();
    if(j.valid){
      box.innerHTML = `<div class="verdict ok"><div class="mark">✓</div><div><div class="vt">Valid signature</div><div class="vs">This proof was signed by the DID below</div></div></div>
        <dl class="kv">
          <dt>DID</dt><dd>${esc(j.did)}</dd>
          <dt>Artifact</dt><dd>${esc(j.artifact_url)}</dd>
          <dt>Commit</dt><dd>${esc(j.commit)}</dd>
        </dl>`;
    } else {
      box.innerHTML = `<div class="verdict bad"><div class="mark">✕</div><div><div class="vt">Invalid proof</div><div class="vs">${esc(j.error||'signature does not match')}</div></div></div>`;
    }
  } finally { spin('verifySpin',false); }
};

document.getElementById('exploreForm').onsubmit = async (e)=>{
  e.preventDefault();
  const box=document.getElementById('exploreResult');
  const did=document.getElementById('did').value.trim();
  const rooms=document.getElementById('rooms').value.trim();
  const win=document.getElementById('window').value.trim();
  if(!did){ box.innerHTML='<span class="pill bad">Enter a did:key</span>'; return; }
  spin('exploreSpin',true);
  try {
    const r=await fetch('/explore?did='+encodeURIComponent(did)+'&rooms='+encodeURIComponent(rooms)+'&window='+encodeURIComponent(win));
    const j=await r.json();
    if(j.error){ box.innerHTML=`<span class="pill bad">${esc(j.error)}</span>`; return; }
    const sig = (j.possible_bot_signals||[]);
    const sigHtml = sig.length
      ? `<div class="chips">${sig.map(s=>`<span class="chip">${esc(s)}</span>`).join('')}</div>`
      : `<span class="pill ok">No bot signals</span>`;
    const notes = (j.notes||[]).map(n=>`<div style="font-size:.78rem;color:var(--muted);margin-top:.4rem">${esc(n)}</div>`).join('');
    box.innerHTML = `
      <div style="margin-bottom:.8rem"><span class="pill ${j.valid_did?'ok':'bad'}">${j.valid_did?'✓ Valid did:key':'✕ Invalid did:key'}</span></div>
      <div class="stats">
        <div class="stat"><div class="n">${j.message_count||0}</div><div class="l">posts found</div></div>
        <div class="stat"><div class="n">${j.unique_texts||0}</div><div class="l">unique texts</div></div>
        <div class="stat"><div class="n">${Math.round((j.duplicate_text_ratio||0)*100)}%</div><div class="l">duplicate</div></div>
      </div>
      <div style="font-size:.82rem;color:var(--muted);font-weight:500">Bot signals</div>
      ${sigHtml}
      ${notes}
      <details><summary>Raw JSON</summary><pre>${esc(JSON.stringify(j,null,2))}</pre></details>`;
  } finally { spin('exploreSpin',false); }
};

let es=null;
document.getElementById('followForm').onsubmit = (e)=>{
  e.preventDefault();
  const did=document.getElementById('fdid').value.trim();
  const rooms=document.getElementById('frooms').value.trim();
  const box=document.getElementById('stream');
  box.style.display='block'; box.textContent='-- waiting for live posts --\\n';
  document.getElementById('stopBtn').style.display='inline-block';
  if(es) es.close();
  es=new EventSource('/follow?did='+encodeURIComponent(did)+'&rooms='+encodeURIComponent(rooms));
  es.onmessage=(ev)=>{ box.textContent += ev.data + '\\n'; box.scrollTop=box.scrollHeight; };
  es.onerror=()=>{ box.textContent += '[stream ended]\\n'; es.close(); es=null; document.getElementById('stopBtn').style.display='none'; };
};
document.getElementById('stopBtn').onclick=()=>{ if(es){ es.close(); es=null; } document.getElementById('stopBtn').style.display='none'; };
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
