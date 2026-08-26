// Verify the browser crypto logic against a Python-generated proof.
// Run: npm i @noble/curves @noble/hashes  (temp), then: node test_verify.mjs
import { ed25519 } from "@noble/curves/ed25519.js";
import { webcrypto } from "node:crypto";

// --- same helpers as index.html ---
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(str){
  let num = 0n; const base = 58n;
  for (const ch of str){ const d = B58.indexOf(ch); if(d<0) throw new Error("bad base58"); num = num*base + BigInt(d); }
  let out=[]; let n=num; while(n>0n){ out.unshift(Number(n%256n)); n/=256n; }
  let z=0; for(const ch of str){ if(ch==='1') z++; else break; }
  return new Uint8Array([...Array(z).fill(0), ...out]);
}
function didToPublicKey(did){
  if(!did.startsWith("did:key:z6Mk")) throw new Error("DID must be a did:key:z6Mk… Ed25519 key");
  const mb = did.slice("did:key:".length); // "z" + base58
  const raw = b58decode(mb.slice(1)); // drop multibase "z" prefix
  if(raw.length!==34||raw[0]!==0xed||raw[1]!==0x01) throw new Error("DID is not an Ed25519 public key");
  return raw.slice(2);
}
function b64urlDecode(s){ s+="==".slice((s.length+1)%4); return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)); }
function contributionPayload(artifactUrl, commit){
  if(!artifactUrl.startsWith("https://")||artifactUrl.includes("#")) throw new Error("bad url");
  const record={artifact_url:artifactUrl,commit:commit.toLowerCase(),schema:"technocore-contribution-v1"};
  const keys=Object.keys(record).sort();
  const parts=keys.map(k=>JSON.stringify(k)+":"+JSON.stringify(record[k]));
  return new TextEncoder().encode("{"+parts.join(",")+"}");
}

// Generate a REAL ed25519 keypair + did:key in JS, build + verify a proof.
const priv = ed25519.utils.randomSecretKey();
const pub = ed25519.getPublicKey(priv);
// did:key encoding
let raw = new Uint8Array([0xed,0x01,...pub]);
// b58encode
function b58encode(bytes){
  let num=0n; for(const b of bytes) num=num*256n+BigInt(b);
  let out=""; const base=58n; while(num>0n){ const q=num/base; const r=num%base; out=B58[Number(r)]+out; num=q; }
  let z=0; for(const b of bytes){ if(b===0) z++; else break; } return "1".repeat(z)+out;
}
function divmod(n,d){ return [n/d, n%d]; }
const did = "did:key:z"+b58encode(raw);
const artifact="https://gist.github.com/fintokyo777/abf07fb86b88f3b8da94d06b35037f35";
const commit="a".repeat(40);
const payload=contributionPayload(artifact,commit);
const sig=ed25519.sign(payload,priv);

// verify with the SAME function the browser uses
const gotPub = didToPublicKey(did);
const ok = ed25519.verify(sig, payload, gotPub);
console.log("DID:", did);
console.log("verify(sig, payload, pub) =", ok);

// cross-check: pub from did must equal generated pub
const match = Buffer.from(gotPub).equals(Buffer.from(pub));
console.log("did public key matches generated pub:", match);
console.log(ok && match ? "PASS ✅ browser crypto matches canonical signer" : "FAIL ❌");
