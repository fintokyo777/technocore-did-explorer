// Cross-check: verify a PYTHON-generated proof using the JS browser logic.
import { ed25519 } from "@noble/curves/ed25519.js";
import { readFileSync } from "node:fs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(str){let num=0n;const base=58n;for(const ch of str){const d=B58.indexOf(ch);if(d<0)throw new Error("bad base58");num=num*base+BigInt(d);}let out=[];let n=num;while(n>0n){out.unshift(Number(n%256n));n/=256n;}let z=0;for(const ch of str){if(ch==='1')z++;else break;}return new Uint8Array([...Array(z).fill(0),...out]);}
function didToPublicKey(did){if(!did.startsWith("did:key:z6Mk"))throw new Error("bad DID");const mb=did.slice(8);const raw=b58decode(mb.slice(1));if(raw.length!==34||raw[0]!==0xed||raw[1]!==0x01)throw new Error("not ed25519");return raw.slice(2);}
function b64urlDecode(s){s+="==".slice((s.length+1)%4);return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
function contributionPayload(artifactUrl,commit){if(!artifactUrl.startsWith("https://")||artifactUrl.includes("#"))throw new Error("bad url");if(artifactUrl.includes("@")){const host=artifactUrl.split("://",2)[1].split("/",2)[0];if(host.includes("@"))throw new Error("creds");}if(!/^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(commit))throw new Error("bad commit");const record={artifact_url:artifactUrl,commit:commit.toLowerCase(),schema:"technocore-contribution-v1"};const keys=Object.keys(record).sort();const parts=keys.map(k=>JSON.stringify(k)+":"+JSON.stringify(record[k]));return new TextEncoder().encode("{"+parts.join(",")+"}");}

const p = JSON.parse(readFileSync("/tmp/py_proof.json","utf8"));
const pub = didToPublicKey(p.did);
const payload = contributionPayload(p.artifact_url, p.commit);
const sig = b64urlDecode(p.signature);
const ok = ed25519.verify(sig, payload, pub);
console.log("Python proof DID:", p.did);
console.log("JS verifies Python proof =", ok);
console.log(ok ? "INTEROP PASS ✅" : "INTEROP FAIL ❌");
