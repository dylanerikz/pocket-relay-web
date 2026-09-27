(() => {
"use strict";

const API="https://api.github.com/repos/dylanerikz/briar-courier-transport/contents/";
const LEDGER_FILE="courier-replay-ledger-v1.json";
const LEDGER_SCHEMA="briar-courier-replay-ledger-v1";
const td=new TextDecoder(),te=new TextEncoder();
let selectedCourier=null;

const U={
  status:document.getElementById("courierInboxStatus"),
  auth:document.getElementById("courierInboxAuth"),
  target:document.getElementById("courierInboxTarget"),
  replay:document.getElementById("courierReplayStatus"),
  stageStatus:document.getElementById("courierStageStatus"),
  message:document.getElementById("courierInboxMessage"),
  payload:document.getElementById("courierInboxPayload"),
  check:document.getElementById("courierInboxCheck"),
  stage:document.getElementById("courierStageAction"),
  ferryAction:document.getElementById("action"),
  ferryGo:document.getElementById("go"),
  receipt:document.getElementById("receipt"),
  state:document.getElementById("state"),
  log:document.getElementById("log")
};

function log(x){if(U.log){U.log.textContent+="\n"+new Date().toISOString()+"  "+x;U.log.scrollTop=U.log.scrollHeight}}
function state(x){if(U.state)U.state.textContent=x}
async function shaText(s){const h=new Uint8Array(await crypto.subtle.digest("SHA-256",te.encode(s)));return[...h].map(b=>b.toString(16).padStart(2,"0")).join("")}
function blankLedger(){return{schema:LEDGER_SCHEMA,version:1,updated_utc:new Date().toISOString(),messages:{},actions:{},reservations:{}}}
async function metaDir(){const r=await navigator.storage.getDirectory();return await r.getDirectoryHandle("meta",{create:true})}
async function readJson(d,n){try{const h=await d.getFileHandle(n),f=await h.getFile();return JSON.parse(await f.text())}catch{return null}}
async function writeJson(d,n,o){const h=await d.getFileHandle(n,{create:true}),w=await h.createWritable();await w.write(JSON.stringify(o,null,2)+"\n");await w.close()}
function validateLedger(l){if(!l||l.schema!==LEDGER_SCHEMA||typeof l.messages!=="object"||typeof l.actions!=="object"||typeof l.reservations!=="object")throw Error("REPLAY_LEDGER_SCHEMA_REJECTED");return l}
async function loadLedger(){const d=await metaDir(),l=await readJson(d,LEDGER_FILE);return l?validateLedger(l):blankLedger()}
async function locked(fn){if(navigator.locks?.request)return await navigator.locks.request("pocket-relay-courier-replay-ledger",{mode:"exclusive"},fn);return await fn()}
async function mutateLedger(fn){return await locked(async()=>{const d=await metaDir();let l=await readJson(d,LEDGER_FILE);l=l?validateLedger(l):blankLedger();const out=await fn(l);l.updated_utc=new Date().toISOString();await writeJson(d,LEDGER_FILE,l);return out})}
function replayState(l,m,a){if(l.messages[m])return{state:"CONSUMED_MESSAGE",record:l.messages[m]};if(l.actions[a])return{state:"CONSUMED_ACTION",record:l.actions[a]};if(l.reservations[m])return{state:"RESERVED",record:l.reservations[m]};return{state:"AVAILABLE",record:null}}

async function greenReceipt(actionId){try{const r=await navigator.storage.getDirectory(),d=await r.getDirectoryHandle("receipts"),o=await readJson(d,actionId+"-receipt.json");return o?.actionID===actionId&&o?.result==="GREEN"?o:null}catch{return null}}
async function migrateReceipt(env,inner){const receipt=await greenReceipt(inner.action_id);if(!receipt)return false;return await mutateLedger(async l=>{if(replayState(l,env.message_id,inner.action_id).state!=="AVAILABLE")return false;const t=receipt.finishedUTC||new Date().toISOString();l.messages[env.message_id]={action_id:inner.action_id,workspace_id:inner.target.workspace_id,sequence:inner.sequence,consumed_utc:t,receipt_result:"GREEN",source:"MIGRATED_GREEN_RECEIPT"};l.actions[inner.action_id]={message_id:env.message_id,consumed_utc:t,source:"MIGRATED_GREEN_RECEIPT"};return true})}

function resetStage(){selectedCourier=null;U.stage.disabled=true;U.stageStatus.textContent="PENDING"}
function clearProvenance(){delete U.ferryAction.dataset.courierMessageId;delete U.ferryAction.dataset.courierActionId;delete U.ferryAction.dataset.courierActionSha256}
function fail(m){resetStage();U.status.textContent="RED";U.auth.textContent="REJECTED";U.target.textContent="PENDING";U.replay.textContent="BLOCKED";state("RED");log("COURIER_INBOX=RED "+m);throw Error(m)}
async function getJson(url){const r=await fetch(url,{cache:"no-store",headers:{Accept:"application/vnd.github+json"}});if(!r.ok)throw Error("COURIER_HTTP_"+r.status);return await r.json()}
function gh64(s){const raw=atob(String(s||"").replace(/\s+/g,""));return td.decode(Uint8Array.from(raw,c=>c.charCodeAt(0)))}
async function entryText(e){const f=await getJson(e.url);if(f.encoding==="base64"&&f.content)return gh64(f.content);if(f.download_url){const r=await fetch(f.download_url,{cache:"no-store"});if(!r.ok)throw Error("COURIER_RAW_HTTP_"+r.status);return await r.text()}throw Error("COURIER_FILE_CONTENT_UNAVAILABLE")}
function isHex(s,n){return typeof s==="string"&&new RegExp("^[0-9a-f]{"+n+"}$").test(s)}
function outer(env,name){if(env?.schema!=="briar-courier-envelope-v1")throw Error("ENVELOPE_SCHEMA_REJECTED");if(!isHex(env.message_id,32))throw Error("MESSAGE_ID_REJECTED");if(name!==env.message_id+".bce")throw Error("MESSAGE_FILENAME_MISMATCH");if(!isHex(env.recipient_key_id,64))throw Error("RECIPIENT_KEY_ID_REJECTED");const k=env.ephemeral_public_key_jwk;if(!k||k.kty!=="EC"||k.crv!=="P-256"||typeof k.x!=="string"||typeof k.y!=="string")throw Error("EPHEMERAL_KEY_REJECTED");const C=window.BriarCourierCrypto,s=C.b64uDecode(env.hkdf_salt_b64u||""),n=C.b64uDecode(env.aes_gcm_nonce_b64u||""),c=C.b64uDecode(env.ciphertext_b64u||"");if(s.length!==32)throw Error("HKDF_SALT_LENGTH_REJECTED");if(n.length!==12)throw Error("AES_GCM_NONCE_LENGTH_REJECTED");if(c.length<16||c.length>2*1024*1024)throw Error("CIPHERTEXT_LENGTH_REJECTED")}
function time(s,l){const x=Date.parse(s);if(!Number.isFinite(x))throw Error(l+"_TIME_REJECTED");return x}
function inner(o,env,id){if(o?.schema!=="briar-courier-action-v1")throw Error("INNER_SCHEMA_REJECTED");if(o.message_id!==env.message_id)throw Error("INNER_OUTER_MESSAGE_ID_MISMATCH");if(!o.action_id||typeof o.action_id!=="string")throw Error("ACTION_ID_REJECTED");if(!Number.isInteger(o.sequence)||o.sequence<1)throw Error("SEQUENCE_REJECTED");if(o.target?.device_key_id!==id.key_id)throw Error("INNER_DEVICE_TARGET_MISMATCH");if(!o.target?.workspace_id)throw Error("WORKSPACE_TARGET_REJECTED");const a=time(o.created_utc,"CREATED"),b=time(o.expires_utc,"EXPIRES"),now=Date.now();if(a>now+300000)throw Error("MESSAGE_FROM_FUTURE_REJECTED");if(b<=a)throw Error("EXPIRY_ORDER_REJECTED");if(now>=b)throw Error("MESSAGE_EXPIRED");const p=o.pocket_action;if(!p||p.schemaVersion!==1||p.actionID!==o.action_id||!Array.isArray(p.replacements))throw Error("POCKET_ACTION_REJECTED")}
async function workspaceName(){try{const r=await navigator.storage.getDirectory(),d=await r.getDirectoryHandle("meta"),h=await d.getFileHandle("workspace.json"),f=await h.getFile();return JSON.parse(await f.text())?.name||null}catch{return null}}

async function checkInbox(){
  if(!window.BriarCourierCrypto?.supported())return fail("CRYPTO_UNSUPPORTED");
  resetStage();state("INBOX");U.status.textContent="CHECKING";U.auth.textContent="PENDING";U.target.textContent="PENDING";U.replay.textContent="CHECKING";U.message.value="None";U.payload.value="Checking public Courier transport...";
  const id=await window.BriarCourierCrypto.loadDeviceIdentity();if(!id?.privateKey||!id?.key_id)return fail("CRYPTO_KEY_MISSING");
  const list=await getJson(API);if(!Array.isArray(list))return fail("COURIER_LISTING_REJECTED");
  const candidates=list.filter(x=>x?.type==="file"&&x.name?.endsWith(".bce")&&x.url),valid=[],errors=[];
  for(const e of candidates){let env;try{const t=await entryText(e);if(t.length>3*1024*1024)throw Error("ENVELOPE_TEXT_TOO_LARGE");env=JSON.parse(t);outer(env,e.name)}catch(err){log("COURIER_ENVELOPE_SKIP="+e.name+" ERROR="+(err.message||err));continue}if(env.recipient_key_id!==id.key_id)continue;try{const bytes=await window.BriarCourierCrypto.decryptActionEnvelope(id,env),obj=JSON.parse(td.decode(bytes));inner(obj,env,id);let l=await loadLedger(),rp=replayState(l,env.message_id,obj.action_id);if(rp.state==="AVAILABLE"&&await migrateReceipt(env,obj)){l=await loadLedger();rp=replayState(l,env.message_id,obj.action_id);log("COURIER_REPLAY_MIGRATION=GREEN MESSAGE_ID="+env.message_id+" ACTION_ID="+obj.action_id)}valid.push({env,inner:obj,replay:rp})}catch(err){errors.push({name:e.name,error:String(err.message||err)})}}
  if(!valid.length){if(errors.length){U.payload.value=JSON.stringify(errors,null,2);return fail("ADDRESSED_ENVELOPE_REJECTED")}U.status.textContent="NO MAIL";U.auth.textContent="N/A";U.target.textContent="N/A";U.replay.textContent="GREEN / NO MAIL";U.stageStatus.textContent="N/A";U.payload.value="No valid envelope addressed to this device.";state("GREEN");return}
  valid.sort((a,b)=>Date.parse(b.inner.created_utc)-Date.parse(a.inner.created_utc));const ws=await workspaceName();const selected=valid.find(v=>v.inner.target.workspace_id===ws&&v.replay.state==="AVAILABLE")||valid.find(v=>v.inner.target.workspace_id===ws)||valid[0];const match=!!ws&&selected.inner.target.workspace_id===ws;
  U.status.textContent="DECRYPTED";U.auth.textContent="AES-GCM GREEN";U.target.textContent=match?ws+" / GREEN":(ws?"MISMATCH: "+ws:"NO WORKSPACE LOADED");U.message.value=selected.env.message_id;U.payload.value=JSON.stringify(selected.inner,null,2);
  if(!match){U.replay.textContent=selected.replay.state;U.stageStatus.textContent="BLOCKED";state("REVIEW")}else if(selected.replay.state==="AVAILABLE"){selectedCourier=selected;U.stage.disabled=false;U.replay.textContent="GREEN / AVAILABLE";U.stageStatus.textContent="READY";state("GREEN")}else{U.replay.textContent=selected.replay.state;U.stageStatus.textContent="BLOCKED / REPLAY";state("GUARDED")}
  log("COURIER_INBOX=GREEN MESSAGE_ID="+selected.env.message_id+" AUTH=GREEN TARGET="+(match?"GREEN":"REVIEW")+" REPLAY="+selected.replay.state+" STAGE="+(U.stage.disabled?"BLOCKED":"READY")+" EXECUTED=FALSE")
}

async function stageAction(){if(!selectedCourier)throw Error("NO_VERIFIED_COURIER_ACTION");const rp=replayState(await loadLedger(),selectedCourier.env.message_id,selectedCourier.inner.action_id);if(rp.state!=="AVAILABLE")throw Error("COURIER_REPLAY_BLOCKED_"+rp.state);const text=JSON.stringify(selectedCourier.inner.pocket_action,null,2),hash=await shaText(text);U.ferryAction.value=text;U.ferryAction.dataset.courierMessageId=selectedCourier.env.message_id;U.ferryAction.dataset.courierActionId=selectedCourier.inner.action_id;U.ferryAction.dataset.courierActionSha256=hash;U.stageStatus.textContent="STAGED / GO REQUIRED";state("STAGED");log("COURIER_STAGE=GREEN MESSAGE_ID="+selectedCourier.env.message_id+" ACTION_ID="+selectedCourier.inner.action_id+" ACTION_SHA256="+hash+" EXECUTED=FALSE HUMAN_GO_REQUIRED=TRUE");U.ferryAction.scrollIntoView({behavior:"smooth",block:"center"})}

async function reserve(){const m=U.ferryAction.dataset.courierMessageId,a=U.ferryAction.dataset.courierActionId,h=U.ferryAction.dataset.courierActionSha256;if(!m&&!a&&!h)return null;if(!m||!a||!h)throw Error("COURIER_STAGE_METADATA_INCOMPLETE");if(await shaText(U.ferryAction.value)!==h)throw Error("COURIER_STAGED_ACTION_CHANGED");const obj=JSON.parse(U.ferryAction.value);if(obj.actionID!==a)throw Error("COURIER_STAGED_ACTION_ID_MISMATCH");const ticket=await mutateLedger(async l=>{const rp=replayState(l,m,a);if(rp.state!=="AVAILABLE")throw Error("COURIER_REPLAY_BLOCKED_"+rp.state);const t=new Date().toISOString();l.reservations[m]={action_id:a,action_sha256:h,reserved_utc:t};return{message_id:m,action_id:a,action_sha256:h,reserved_utc:t}});U.replay.textContent="RESERVED";U.stageStatus.textContent="EXECUTION RESERVED";log("COURIER_REPLAY_RESERVE=GREEN MESSAGE_ID="+m+" ACTION_ID="+a);return ticket}
async function finalize(ticket,receipt){if(!receipt||receipt.actionID!==ticket.action_id||receipt.result!=="GREEN")throw Error("COURIER_GREEN_RECEIPT_REQUIRED");await mutateLedger(async l=>{const r=l.reservations[ticket.message_id];if(!r||r.action_id!==ticket.action_id||r.action_sha256!==ticket.action_sha256)throw Error("COURIER_RESERVATION_MISSING");const t=receipt.finishedUTC||new Date().toISOString();l.messages[ticket.message_id]={action_id:ticket.action_id,consumed_utc:t,receipt_result:"GREEN",source:"LIVE_COURIER_EXECUTION"};l.actions[ticket.action_id]={message_id:ticket.message_id,consumed_utc:t,source:"LIVE_COURIER_EXECUTION"};delete l.reservations[ticket.message_id]});U.replay.textContent="CONSUMED";U.stageStatus.textContent="CONSUMED / REPLAY BLOCKED";U.stage.disabled=true;selectedCourier=null;clearProvenance();state("GREEN");log("COURIER_REPLAY_CONSUME=GREEN MESSAGE_ID="+ticket.message_id+" ACTION_ID="+ticket.action_id)}
async function release(ticket,why){if(!ticket)return;await mutateLedger(async l=>{if(l.reservations[ticket.message_id]?.action_id===ticket.action_id)delete l.reservations[ticket.message_id]});U.replay.textContent="GREEN / AVAILABLE";U.stageStatus.textContent="STAGED / RETRY AVAILABLE";log("COURIER_REPLAY_RELEASE=GREEN MESSAGE_ID="+ticket.message_id+" ACTION_ID="+ticket.action_id+" REASON="+String(why||"NO_GREEN_RECEIPT").replace(/\s+/g,"_").slice(0,120))}
function receiptNow(){try{return JSON.parse(U.receipt.value||"")}catch{return null}}

function installGoGuard(){if(!U.ferryGo||typeof U.ferryGo.onclick!=="function"){log("COURIER_REPLAY_GO_WRAP=RED ORIGINAL_HANDLER_MISSING");return}const original=U.ferryGo.onclick;U.ferryGo.onclick=async e=>{const courier=!!(U.ferryAction.dataset.courierMessageId||U.ferryAction.dataset.courierActionId||U.ferryAction.dataset.courierActionSha256);if(!courier)return await original.call(U.ferryGo,e);let ticket;const before=U.receipt.value||"";try{ticket=await reserve()}catch(err){U.replay.textContent="BLOCKED";U.stageStatus.textContent="BLOCKED / REPLAY";state("GUARDED");log("COURIER_REPLAY_PREFLIGHT=RED "+(err.message||err));alert(err.message||err);return}await original.call(U.ferryGo,e);const after=U.receipt.value||"",r=receiptNow();if(after!==before&&r?.actionID===ticket.action_id&&r?.result==="GREEN"){try{await finalize(ticket,r)}catch(err){U.replay.textContent="RESERVED / REVIEW";U.stageStatus.textContent="LEDGER FINALIZE FAILED";state("RED");log("COURIER_REPLAY_FINALIZE=RED "+(err.message||err));alert("Action returned GREEN, but replay finalization failed. Reservation remains blocking replay.\n\n"+(err.message||err))}return}try{await release(ticket,r?.error||"NO_NEW_GREEN_RECEIPT")}catch(err){U.replay.textContent="RESERVED / REVIEW";U.stageStatus.textContent="RESERVATION REVIEW";state("RED");log("COURIER_REPLAY_RELEASE=RED "+(err.message||err))}};log("COURIER_REPLAY_GO_WRAP=GREEN")}

U.check?.addEventListener("click",async()=>{U.check.disabled=true;try{await checkInbox()}catch(e){if(U.status.textContent!=="RED"){U.status.textContent="RED";U.auth.textContent="REJECTED";U.replay.textContent="BLOCKED";U.stageStatus.textContent="BLOCKED";state("RED");log("COURIER_INBOX=RED "+(e.message||e))}alert(e.message||e)}finally{U.check.disabled=false}});
U.stage?.addEventListener("click",async()=>{try{await stageAction()}catch(e){U.stageStatus.textContent="RED";state("RED");log("COURIER_STAGE=RED "+(e.message||e));alert(e.message||e)}});
installGoGuard();
log("COURIER_INBOX_MODULE=GREEN MODE=REPLAY_LEDGER_STAGE_MANUAL_GO");
})();
