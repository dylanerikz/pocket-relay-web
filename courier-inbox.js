(() => {
"use strict";

const COURIER_CONTENTS_API =
  "https://api.github.com/repos/dylanerikz/briar-courier-transport/contents/";

const td = new TextDecoder();
let selectedCourier = null;

const U = {
  status: document.getElementById("courierInboxStatus"),
  auth: document.getElementById("courierInboxAuth"),
  target: document.getElementById("courierInboxTarget"),
  stageStatus: document.getElementById("courierStageStatus"),
  message: document.getElementById("courierInboxMessage"),
  payload: document.getElementById("courierInboxPayload"),
  check: document.getElementById("courierInboxCheck"),
  stage: document.getElementById("courierStageAction"),
  ferryAction: document.getElementById("action"),
  ferryGo: document.getElementById("go"),
  state: document.getElementById("state"),
  log: document.getElementById("log")
};

function log(line) {
  if (!U.log) return;
  U.log.textContent += "\n" + new Date().toISOString() + "  " + line;
  U.log.scrollTop = U.log.scrollHeight;
}

function setState(x) {
  if (U.state) U.state.textContent = x;
}

function resetStage() {
  selectedCourier = null;
  U.stage.disabled = true;
  U.stageStatus.textContent = "PENDING";
}

function fail(message) {
  resetStage();
  U.status.textContent = "RED";
  U.auth.textContent = "REJECTED";
  U.target.textContent = "PENDING";
  setState("RED");
  log("COURIER_INBOX=RED " + message);
  throw new Error(message);
}

async function getJson(url) {
  const r = await fetch(url, {
    cache: "no-store",
    headers: { "Accept": "application/vnd.github+json" }
  });
  if (!r.ok) throw new Error("COURIER_HTTP_" + r.status);
  return await r.json();
}

function decodeGithubBase64(s) {
  const raw = atob(String(s || "").replace(/\s+/g, ""));
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  return td.decode(bytes);
}

async function getEntryText(entry) {
  const file = await getJson(entry.url);
  if (file.encoding === "base64" && file.content) {
    return decodeGithubBase64(file.content);
  }
  if (file.download_url) {
    const r = await fetch(file.download_url, { cache: "no-store" });
    if (!r.ok) throw new Error("COURIER_RAW_HTTP_" + r.status);
    return await r.text();
  }
  throw new Error("COURIER_FILE_CONTENT_UNAVAILABLE");
}

function isHex(s, n) {
  return typeof s === "string" &&
    new RegExp("^[0-9a-f]{" + n + "}$").test(s);
}

function validateOuter(env, filename) {
  if (!env || env.schema !== "briar-courier-envelope-v1") {
    throw new Error("ENVELOPE_SCHEMA_REJECTED");
  }
  if (!isHex(env.message_id, 32)) {
    throw new Error("MESSAGE_ID_REJECTED");
  }
  if (filename !== env.message_id + ".bce") {
    throw new Error("MESSAGE_FILENAME_MISMATCH");
  }
  if (!isHex(env.recipient_key_id, 64)) {
    throw new Error("RECIPIENT_KEY_ID_REJECTED");
  }

  const epk = env.ephemeral_public_key_jwk;
  if (!epk || epk.kty !== "EC" || epk.crv !== "P-256" ||
      typeof epk.x !== "string" || typeof epk.y !== "string") {
    throw new Error("EPHEMERAL_KEY_REJECTED");
  }

  const C = window.BriarCourierCrypto;
  const salt = C.b64uDecode(env.hkdf_salt_b64u || "");
  const nonce = C.b64uDecode(env.aes_gcm_nonce_b64u || "");
  const cipher = C.b64uDecode(env.ciphertext_b64u || "");

  if (salt.length !== 32) throw new Error("HKDF_SALT_LENGTH_REJECTED");
  if (nonce.length !== 12) throw new Error("AES_GCM_NONCE_LENGTH_REJECTED");
  if (cipher.length < 16) throw new Error("CIPHERTEXT_TOO_SHORT");
  if (cipher.length > 2 * 1024 * 1024) throw new Error("CIPHERTEXT_TOO_LARGE");
}

function parseUtc(s, label) {
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) throw new Error(label + "_TIME_REJECTED");
  return ms;
}

function validateInner(inner, env, identity) {
  if (!inner || inner.schema !== "briar-courier-action-v1") {
    throw new Error("INNER_SCHEMA_REJECTED");
  }
  if (inner.message_id !== env.message_id) {
    throw new Error("INNER_OUTER_MESSAGE_ID_MISMATCH");
  }
  if (!inner.action_id || typeof inner.action_id !== "string") {
    throw new Error("ACTION_ID_REJECTED");
  }
  if (!Number.isInteger(inner.sequence) || inner.sequence < 1) {
    throw new Error("SEQUENCE_REJECTED");
  }
  if (inner.target?.device_key_id !== identity.key_id) {
    throw new Error("INNER_DEVICE_TARGET_MISMATCH");
  }
  if (!inner.target?.workspace_id ||
      typeof inner.target.workspace_id !== "string") {
    throw new Error("WORKSPACE_TARGET_REJECTED");
  }

  const created = parseUtc(inner.created_utc, "CREATED");
  const expires = parseUtc(inner.expires_utc, "EXPIRES");
  const now = Date.now();

  if (created > now + 5 * 60 * 1000) {
    throw new Error("MESSAGE_FROM_FUTURE_REJECTED");
  }
  if (expires <= created) {
    throw new Error("EXPIRY_ORDER_REJECTED");
  }
  if (now >= expires) {
    throw new Error("MESSAGE_EXPIRED");
  }

  const a = inner.pocket_action;
  if (!a || a.schemaVersion !== 1 ||
      a.actionID !== inner.action_id ||
      !Array.isArray(a.replacements)) {
    throw new Error("POCKET_ACTION_REJECTED");
  }
}

async function loadWorkspaceName() {
  try {
    const root = await navigator.storage.getDirectory();
    const meta = await root.getDirectoryHandle("meta");
    const handle = await meta.getFileHandle("workspace.json");
    const file = await handle.getFile();
    const obj = JSON.parse(await file.text());
    return obj?.name || null;
  } catch {
    return null;
  }
}

async function checkInbox() {
  if (!window.BriarCourierCrypto?.supported()) {
    return fail("CRYPTO_UNSUPPORTED");
  }

  resetStage();
  setState("INBOX");
  U.status.textContent = "CHECKING";
  U.auth.textContent = "PENDING";
  U.target.textContent = "PENDING";
  U.message.value = "None";
  U.payload.value = "Checking public Courier transport...";

  const identity = await window.BriarCourierCrypto.loadDeviceIdentity();
  if (!identity?.privateKey || !identity?.key_id) {
    return fail("CRYPTO_KEY_MISSING");
  }

  const listing = await getJson(COURIER_CONTENTS_API);
  if (!Array.isArray(listing)) {
    return fail("COURIER_LISTING_REJECTED");
  }

  const candidates = listing.filter(x =>
    x?.type === "file" &&
    typeof x.name === "string" &&
    x.name.endsWith(".bce") &&
    x.url
  );

  if (!candidates.length) {
    U.status.textContent = "EMPTY";
    U.auth.textContent = "N/A";
    U.target.textContent = "N/A";
    U.stageStatus.textContent = "N/A";
    U.payload.value = "No Courier envelopes found.";
    setState("GREEN");
    log("COURIER_INBOX=GREEN ENVELOPES=0");
    return;
  }

  const valid = [];
  const addressedErrors = [];

  for (const entry of candidates) {
    let env;
    try {
      const text = await getEntryText(entry);
      if (text.length > 3 * 1024 * 1024) {
        throw new Error("ENVELOPE_TEXT_TOO_LARGE");
      }
      env = JSON.parse(text);
      validateOuter(env, entry.name);
    } catch (e) {
      log("COURIER_ENVELOPE_SKIP=" + entry.name + " ERROR=" + (e.message || e));
      continue;
    }

    if (env.recipient_key_id !== identity.key_id) {
      continue;
    }

    try {
      const bytes = await window.BriarCourierCrypto.decryptActionEnvelope(identity, env);
      const inner = JSON.parse(td.decode(bytes));
      validateInner(inner, env, identity);
      valid.push({ env, inner });
    } catch (e) {
      addressedErrors.push({
        name: entry.name,
        error: String(e.message || e)
      });
    }
  }

  if (!valid.length) {
    if (addressedErrors.length) {
      U.payload.value = JSON.stringify(addressedErrors, null, 2);
      return fail("ADDRESSED_ENVELOPE_REJECTED");
    }

    U.status.textContent = "NO MAIL";
    U.auth.textContent = "N/A";
    U.target.textContent = "N/A";
    U.stageStatus.textContent = "N/A";
    U.payload.value = "No valid envelope addressed to this device.";
    setState("GREEN");
    log("COURIER_INBOX=GREEN ADDRESSED=0");
    return;
  }

  valid.sort((a, b) =>
    Date.parse(b.inner.created_utc) - Date.parse(a.inner.created_utc)
  );

  const selected = valid[0];
  const workspaceName = await loadWorkspaceName();
  const targetMatch =
    !!workspaceName &&
    selected.inner.target.workspace_id === workspaceName;

  U.status.textContent = "DECRYPTED";
  U.auth.textContent = "AES-GCM GREEN";
  U.target.textContent = targetMatch
    ? workspaceName + " / GREEN"
    : (workspaceName
        ? "MISMATCH: " + workspaceName
        : "NO WORKSPACE LOADED");

  U.message.value = selected.env.message_id;
  U.payload.value = JSON.stringify(selected.inner, null, 2);

  if (targetMatch) {
    selectedCourier = selected;
    U.stage.disabled = false;
    U.stageStatus.textContent = "READY";
  } else {
    selectedCourier = null;
    U.stage.disabled = true;
    U.stageStatus.textContent = "BLOCKED";
  }

  setState(targetMatch ? "GREEN" : "REVIEW");
  log(
    "COURIER_INBOX=GREEN MESSAGE_ID=" +
    selected.env.message_id +
    " AUTH=GREEN TARGET=" +
    (targetMatch ? "GREEN" : "REVIEW") +
    " STAGE=" +
    (targetMatch ? "READY" : "BLOCKED") +
    " EXECUTED=FALSE"
  );
}

function stageAction() {
  if (!selectedCourier) throw new Error("NO_VERIFIED_COURIER_ACTION");
  if (!U.ferryAction || !U.ferryGo) throw new Error("BRIAR_FERRY_UNAVAILABLE");

  const action = selectedCourier.inner.pocket_action;
  U.ferryAction.value = JSON.stringify(action, null, 2);
  U.ferryAction.dataset.courierMessageId = selectedCourier.env.message_id;
  U.ferryAction.dataset.courierActionId = selectedCourier.inner.action_id;

  U.stageStatus.textContent = "STAGED / GO REQUIRED";
  setState("STAGED");
  log(
    "COURIER_STAGE=GREEN MESSAGE_ID=" +
    selectedCourier.env.message_id +
    " ACTION_ID=" +
    selectedCourier.inner.action_id +
    " EXECUTED=FALSE HUMAN_GO_REQUIRED=TRUE"
  );

  U.ferryAction.scrollIntoView({ behavior: "smooth", block: "center" });
  U.ferryAction.focus({ preventScroll: true });
}

U.check?.addEventListener("click", async () => {
  U.check.disabled = true;
  try {
    await checkInbox();
  } catch (e) {
    if (U.status.textContent !== "RED") {
      U.status.textContent = "RED";
      U.auth.textContent = "REJECTED";
      U.stageStatus.textContent = "BLOCKED";
      setState("RED");
      log("COURIER_INBOX=RED " + (e.message || e));
    }
    alert(e.message || e);
  } finally {
    U.check.disabled = false;
  }
});

U.stage?.addEventListener("click", () => {
  try {
    stageAction();
  } catch (e) {
    U.stageStatus.textContent = "RED";
    setState("RED");
    log("COURIER_STAGE=RED " + (e.message || e));
    alert(e.message || e);
  }
});

log("COURIER_INBOX_MODULE=GREEN MODE=FETCH_DECRYPT_STAGE_MANUAL_GO");
})();
