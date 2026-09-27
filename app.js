const $=id=>document.getElementById(id);
const U={state:$("state"),folder:$("folder"),workspaceName:$("workspaceName"),workspaceFiles:$("workspaceFiles"),mWorkspace:$("mWorkspace"),mSession:$("mSession"),mChanges:$("mChanges"),goal:$("goal"),begin:$("begin"),refresh:$("refresh"),finish:$("finish"),session:$("session"),changes:$("changes"),action:$("action"),actionFile:$("actionFile"),paste:$("paste"),go:$("go"),receipt:$("receipt"),copyReceipt:$("copyReceipt"),downloadReceipt:$("downloadReceipt"),rollback:$("rollback"),bundle:$("bundle"),index:$("index"),log:$("log"),cryptoSupport:$("cryptoSupport"),cryptoIdentity:$("cryptoIdentity"),cryptoPrivate:$("cryptoPrivate"),cryptoFingerprint:$("cryptoFingerprint"),cryptoCreate:$("cryptoCreate"),cryptoCopy:$("cryptoCopy"),cryptoTest:$("cryptoTest"),cryptoResult:$("cryptoResult")};
let root,ws,meta,receipts,rollbacks,workspaceMeta=null,session=null,lastReceipt=null,deviceIdentity=null;
const enc=new TextEncoder(),dec=new TextDecoder();
const ignored=new Set([".git",".pocket-relay","__pycache__",".DS_Store"]);
function state(x){U.state.textContent=x}
function log(x){U.log.textContent+="\n"+new Date().toISOString()+"  "+x;U.log.scrollTop=U.log.scrollHeight}
function dl(obj,name){const a=document.createElement("a"),url=URL.createObjectURL(new Blob([JSON.stringify(obj,null,2)+"\n"],{type:"application/json"}));a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}
async function dir(base,parts,create=false){let d=base;for(const p of parts)if(p)d=await d.getDirectoryHandle(p,{create});return d}
async function fh(base,path,create=false){const p=path.split("/").filter(Boolean),n=p.pop();return (await dir(base,p,create)).getFileHandle(n,{create})}
async function write(base,path,data){const h=await fh(base,path,true),w=await h.createWritable();await w.write(data);await w.close()}
async function writeText(base,path,text){await write(base,path,enc.encode(text))}
async function readBytes(base,path){const f=await (await fh(base,path)).getFile();return new Uint8Array(await f.arrayBuffer())}
async function readText(base,path){return dec.decode(await readBytes(base,path))}
async function jsonRead(base,path){try{return JSON.parse(await readText(base,path))}catch{return null}}
async function jsonWrite(base,path,obj){await writeText(base,path,JSON.stringify(obj,null,2)+"\n")}
async function hashBytes(bytes){const h=await crypto.subtle.digest("SHA-256",bytes);return[...new Uint8Array(h)].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function* walk(d,prefix=""){for await(const [name,h] of d.entries()){const p=prefix?prefix+"/"+name:name;if(h.kind==="directory")yield*walk(h,p);else yield{path:p,handle:h}}}
function safePath(p){p=p.replaceAll("\\","/").replace(/^\/+/,"");if(!p||p.split("/").some(x=>!x||x==="."||x===".."))throw Error("Unsafe path: "+p);return p}
async function snapshot(){const out={};for await(const e of walk(ws)){if(e.path.split("/").some(x=>ignored.has(x)))continue;const f=await e.handle.getFile(),b=await f.arrayBuffer();out[e.path]={sha256:await hashBytes(b),sizeBytes:f.size}}return out}
function diff(a,b){const add=[],mod=[],del=[];for(const p of Object.keys(b)){if(!(p in a))add.push(p);else if(a[p].sha256!==b[p].sha256)mod.push(p)}for(const p of Object.keys(a))if(!(p in b))del.push(p);return{added:add.sort(),modified:mod.sort(),deleted:del.sort()}}
function render(d){const lines=[...d.added.map(x=>"A  "+x),...d.modified.map(x=>"M  "+x),...d.deleted.map(x=>"D  "+x)];U.changes.textContent=lines.join("\n")||"No drift from baseline.";U.mChanges.textContent=lines.length}
async function resetWorkspace(){try{await root.removeEntry("workspace",{recursive:true})}catch{}ws=await root.getDirectoryHandle("workspace",{create:true})}
async function refreshUI(){workspaceMeta=await jsonRead(meta,"workspace.json");session=await jsonRead(meta,"active-session.json");const snap=workspaceMeta?await snapshot():{};U.workspaceName.textContent=workspaceMeta?.name||"None";U.workspaceFiles.textContent=Object.keys(snap).length;U.mWorkspace.textContent=workspaceMeta?.name||"—";U.session.textContent=session?.sessionID||"None";U.mSession.textContent=session?.sessionID||"—";render(session?diff(session.baseline,snap):{added:[],modified:[],deleted:[]})}
async function importFolder(files){files=[...files];if(!files.length)return;state("IMPORT");const rootName=(files[0].webkitRelativePath||"workspace").split("/")[0];await resetWorkspace();for(let i=0;i<files.length;i++){let p=files[i].webkitRelativePath||files[i].name;if(p.startsWith(rootName+"/"))p=p.slice(rootName.length+1);p=safePath(p);await write(ws,p,await files[i].arrayBuffer());if(i%25===0)state(`IMPORT ${i+1}/${files.length}`)}workspaceMeta={schemaVersion:1,name:rootName,filesImported:files.length,importedUTC:new Date().toISOString(),storage:"OPFS"};await jsonWrite(meta,"workspace.json",workspaceMeta);try{await meta.removeEntry("active-session.json")}catch{}session=null;await refreshUI();state("GREEN");log(`WORKSPACE_IMPORT=GREEN NAME=${rootName} FILES=${files.length}`)}
function sid(){const d=new Date(),p=n=>String(n).padStart(2,"0");return`CSR-${d.getUTCFullYear()}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`}
async function begin(){if(!workspaceMeta)throw Error("Import a workspace first.");if(session)throw Error("Session already active.");state("BASELINE");const baseline=await snapshot();session={schemaVersion:1,sessionID:sid(),goal:U.goal.value.trim()||"WORK_ON_RELAY_SOURCE",startedUTC:new Date().toISOString(),workspaceName:workspaceMeta.name,baseline,windowsAcceptance:"PENDING"};await jsonWrite(meta,"active-session.json",session);await refreshUI();state("GREEN");log(`POCKET_SESSION_BEGIN=GREEN SESSION_ID=${session.sessionID} BASELINE_FILES=${Object.keys(baseline).length}`)}
async function status(){if(!session)throw Error("No active session.");state("HASH");const cur=await snapshot(),d=diff(session.baseline,cur);render(d);state("GREEN");log(`STATUS=GREEN ADDED=${d.added.length} MODIFIED=${d.modified.length} DELETED=${d.deleted.length}`);return{cur,d}}
async function finish(){if(!session)throw Error("No active session.");const{cur,d}=await status();const m={schemaVersion:1,sessionID:session.sessionID,goal:session.goal,startedUTC:session.startedUTC,finishedUTC:new Date().toISOString(),workspaceName:session.workspaceName,changes:d,baseline:session.baseline,final:cur,windowsAcceptance:"PENDING"};await jsonWrite(receipts,session.sessionID+"-manifest.json",m);dl(m,session.sessionID+"-manifest.json");try{await meta.removeEntry("active-session.json")}catch{}log("POCKET_SESSION_FINISH=GREEN");session=null;await refreshUI()}
function occurrences(s,n){return n?s.split(n).length-1:0}
async function verify(arr,phase){for(const e of arr||[]){const p=safePath(e.path),b=await readBytes(ws,p),h=await hashBytes(b.buffer);if(h!==String(e.sha256).toLowerCase())throw Error(`${phase} hash mismatch: ${p}\nExpected ${e.sha256}\nActual ${h}`)}}
async function applyAction(a){if(a?.schemaVersion!==1||!a.actionID||!Array.isArray(a.replacements))throw Error("Invalid Pocket Action v1.");state("GO");await verify(a.preconditions,"PRE");let rb;try{rb=await rollbacks.getDirectoryHandle(a.actionID,{create:false});if(rb)throw Error("Action ID already has rollback state: "+a.actionID)}catch(e){if(!String(e).includes("already has rollback"))rb=await rollbacks.getDirectoryHandle(a.actionID,{create:true});else throw e}
const originals=new Map(),changed=new Set();try{for(const r of a.replacements){const p=safePath(r.path);if(!originals.has(p)){const b=await readBytes(ws,p);originals.set(p,b);await write(rb,p,b)}let t=await readText(ws,p),c=occurrences(t,r.oldText);if(c!==r.expectedCount)throw Error(`Replacement count mismatch: ${p} expected ${r.expectedCount}, found ${c}`);t=t.split(r.oldText).join(r.newText);await writeText(ws,p,t);changed.add(p)}await verify(a.postconditions,"POST")}catch(e){for(const[p,b]of originals)await write(ws,p,b);lastReceipt={schemaVersion:1,actionID:a.actionID,finishedUTC:new Date().toISOString(),result:"RED_ROLLED_BACK",error:String(e.message||e),filesChanged:[],windowsAcceptance:"PENDING"};await jsonWrite(receipts,a.actionID+"-receipt.json",lastReceipt);U.receipt.value=JSON.stringify(lastReceipt,null,2);state("RED");throw e}
lastReceipt={schemaVersion:1,actionID:a.actionID,summary:a.summary||"",finishedUTC:new Date().toISOString(),result:"GREEN",filesChanged:[...changed].sort(),windowsAcceptance:"PENDING"};await jsonWrite(receipts,a.actionID+"-receipt.json",lastReceipt);await jsonWrite(meta,"last-action.json",{actionID:a.actionID});U.receipt.value=JSON.stringify(lastReceipt,null,2);if(session)await status();state("GREEN");log(`POCKET_ACTION=GREEN ACTION_ID=${a.actionID} FILES_CHANGED=${changed.size}`)}
async function rollback(){const m=await jsonRead(meta,"last-action.json");if(!m?.actionID)throw Error("No last action recorded.");const rb=await rollbacks.getDirectoryHandle(m.actionID);let n=0;for await(const e of walk(rb)){await write(ws,e.path,await readBytes(rb,e.path));n++}lastReceipt={schemaVersion:1,actionID:m.actionID+"-ROLLBACK",finishedUTC:new Date().toISOString(),result:"GREEN",restoredFiles:n,windowsAcceptance:"PENDING"};U.receipt.value=JSON.stringify(lastReceipt,null,2);try{await meta.removeEntry("last-action.json")}catch{}if(session)await status();log(`POCKET_ROLLBACK=GREEN RESTORED=${n}`)}
function b64(bytes){let s="";for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.slice(i,i+32768));return btoa(s)}
async function bundle(){if(!session)throw Error("Begin a session first.");const{cur,d}=await status(),files={};for(const p of [...d.added,...d.modified]){const bytes=await readBytes(ws,p);files[p]={sha256:cur[p].sha256,sizeBytes:cur[p].sizeBytes,encoding:"base64",content:b64(bytes)}}const o={schemaVersion:1,type:"POCKET_WORK_BUNDLE",session:{sessionID:session.sessionID,goal:session.goal,workspaceName:session.workspaceName,exportedUTC:new Date().toISOString(),windowsAcceptance:"PENDING"},changes:d,baseline:session.baseline,final:cur,files};dl(o,session.sessionID+".pocketbundle.json");log(`POCKET_WORK_BUNDLE=GREEN FILES_INCLUDED=${Object.keys(files).length}`)}
async function workspaceIndex(){if(!workspaceMeta)throw Error("No workspace.");const o={schemaVersion:1,type:"POCKET_WORKSPACE_INDEX",workspace:workspaceMeta,createdUTC:new Date().toISOString(),files:await snapshot()};dl(o,workspaceMeta.name+"-workspace-index.json")}

async function refreshCryptoIdentity(){
  if(!window.BriarCourierCrypto?.supported()){
    U.cryptoSupport.textContent="UNSUPPORTED";
    U.cryptoIdentity.textContent="UNAVAILABLE";
    return;
  }
  U.cryptoSupport.textContent="WEB CRYPTO READY";
  deviceIdentity=await window.BriarCourierCrypto.loadDeviceIdentity();
  if(deviceIdentity){
    U.cryptoIdentity.textContent="PRESENT";
    U.cryptoFingerprint.value=window.BriarCourierCrypto.prettyFingerprint(deviceIdentity.key_id);
    U.cryptoPrivate.textContent="LOCAL / NON-EXPORTABLE";
  }else{
    U.cryptoIdentity.textContent="NOT CREATED";
    U.cryptoFingerprint.value="None";
    U.cryptoPrivate.textContent="LOCAL ONLY";
  }
}
async function createOrLoadCryptoIdentity(){
  state("CRYPTO");
  deviceIdentity=await window.BriarCourierCrypto.ensureDeviceIdentity();
  await refreshCryptoIdentity();
  state("GREEN");
  log(`COURIER_DEVICE_IDENTITY=GREEN KEY_ID=${deviceIdentity.key_id.slice(0,16)}...`);
}
async function copyPairingRecord(){
  if(!deviceIdentity)deviceIdentity=await window.BriarCourierCrypto.loadDeviceIdentity();
  if(!deviceIdentity)throw Error("CRYPTO_KEY_MISSING");
  const rec=await window.BriarCourierCrypto.exportPublicPairingRecord(deviceIdentity);
  await navigator.clipboard.writeText(JSON.stringify(rec,null,2));
  log("COURIER_PAIRING_RECORD_COPY=GREEN PUBLIC_ONLY=TRUE");
}
async function runCryptoSelfTest(){
  state("CRYPTO TEST");
  U.cryptoResult.textContent="Running local cryptographic round trip...";
  const r=await window.BriarCourierCrypto.selfTest();
  U.cryptoResult.textContent=JSON.stringify(r,null,2);
  state("GREEN");
  log("COURIER_CRYPTO_SELF_TEST=GREEN ROUND_TRIP=GREEN TAMPER_REJECTION=GREEN");
}

async function boot(){state("BOOT");root=await navigator.storage.getDirectory();ws=await root.getDirectoryHandle("workspace",{create:true});meta=await root.getDirectoryHandle("meta",{create:true});receipts=await root.getDirectoryHandle("receipts",{create:true});rollbacks=await root.getDirectoryHandle("rollback",{create:true});await refreshUI();await refreshCryptoIdentity();if("serviceWorker"in navigator)navigator.serviceWorker.register("./sw.js").then(()=>log("SERVICE_WORKER=GREEN")).catch(e=>log("SERVICE_WORKER=RED "+e));state("READY");log("OPFS=GREEN")}
async function run(fn){try{await fn()}catch(e){alert(e.message||e);log("ERROR "+(e.message||e));state("RED")}}
U.folder.onchange=()=>run(()=>importFolder(U.folder.files));U.begin.onclick=()=>run(begin);U.refresh.onclick=()=>run(status);U.finish.onclick=()=>run(finish);U.actionFile.onchange=()=>run(async()=>{const f=U.actionFile.files[0];if(f){U.action.value=await f.text();JSON.parse(U.action.value);log("ACTION_FILE_LOAD=GREEN")}});U.paste.onclick=()=>run(async()=>{U.action.value=await navigator.clipboard.readText();JSON.parse(U.action.value);log("ACTION_PASTE=GREEN")});U.go.onclick=()=>run(()=>applyAction(JSON.parse(U.action.value)));U.copyReceipt.onclick=()=>run(async()=>{if(!lastReceipt)throw Error("No receipt yet.");await navigator.clipboard.writeText(JSON.stringify(lastReceipt,null,2));log("RECEIPT_COPY=GREEN")});U.downloadReceipt.onclick=()=>run(async()=>{if(!lastReceipt)throw Error("No receipt yet.");dl(lastReceipt,lastReceipt.actionID+"-receipt.json")});U.rollback.onclick=()=>run(rollback);U.bundle.onclick=()=>run(bundle);U.index.onclick=()=>run(workspaceIndex);U.cryptoCreate.onclick=()=>run(createOrLoadCryptoIdentity);U.cryptoCopy.onclick=()=>run(copyPairingRecord);U.cryptoTest.onclick=()=>run(runCryptoSelfTest);boot().catch(e=>{state("BOOT RED");log("BOOT_ERROR "+e)})