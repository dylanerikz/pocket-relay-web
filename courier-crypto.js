(() => {
"use strict";

const DB_NAME = "briar-pocket-relay-crypto";
const DB_VERSION = 1;
const STORE = "device_identity";
const RECORD_KEY = "primary";
const ACTION_INFO = new TextEncoder().encode("BriarCourier/v1/ACTION");
const te = new TextEncoder();
const td = new TextDecoder();

function requireCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new Error("CRYPTO_UNSUPPORTED");
  }
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function toHex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function b64uEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64uDecode(s) {
  const p = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4);
  const raw = atob(p);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function openDb() {
  requireCrypto();
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) {
        req.result.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("CRYPTO_DB_OPEN_FAILED"));
  });
}

async function dbGet(key) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(key);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error("CRYPTO_DB_READ_FAILED"));
    });
  } finally {
    db.close();
  }
}

async function dbPut(key, value) {
  const db = await openDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error || new Error("CRYPTO_DB_WRITE_FAILED"));
      tx.onabort = () => reject(tx.error || new Error("CRYPTO_DB_WRITE_ABORTED"));
    });
  } finally {
    db.close();
  }
}

async function canonicalPublicKeyBytes(publicKey) {
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y
  });
  return te.encode(canonical);
}

async function fingerprintPublicKey(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await canonicalPublicKeyBytes(publicKey)));
  return toHex(digest);
}

function prettyFingerprint(fullHex) {
  return fullHex.slice(0, 32).toUpperCase().match(/.{1,4}/g).join(" ");
}

async function generateDeviceIdentity() {
  requireCrypto();
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const keyId = await fingerprintPublicKey(pair.publicKey);
  const record = {
    schema: "briar-courier-local-device-v1",
    device_id: "pr-" + toHex(randomBytes(8)),
    mailbox_id: toHex(randomBytes(8)),
    key_id: keyId,
    created_utc: new Date().toISOString(),
    publicKey: pair.publicKey,
    privateKey: pair.privateKey
  };
  await dbPut(RECORD_KEY, record);
  return record;
}

async function loadDeviceIdentity() {
  requireCrypto();
  return await dbGet(RECORD_KEY);
}

async function ensureDeviceIdentity() {
  const existing = await loadDeviceIdentity();
  return existing || await generateDeviceIdentity();
}

async function exportPublicPairingRecord(identity) {
  if (!identity?.publicKey || !identity?.key_id) throw new Error("CRYPTO_KEY_MISSING");
  const jwk = await crypto.subtle.exportKey("jwk", identity.publicKey);
  return {
    schema: "briar-courier-device-v1",
    device_id: identity.device_id,
    mailbox_id: identity.mailbox_id,
    key_id: identity.key_id,
    curve: "P-256",
    public_key_jwk: {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y
    },
    created_utc: identity.created_utc
  };
}

async function importPublicJwk(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

async function deriveActionAesKey(privateKey, peerPublicKey, salt) {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256
  );
  const hkdfBase = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: ACTION_INFO
    },
    hkdfBase,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptForDevice(devicePublicKey, recipientKeyId, plaintextBytes) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const salt = randomBytes(32);
  const nonce = randomBytes(12);
  const aes = await deriveActionAesKey(ephemeral.privateKey, devicePublicKey, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    aes,
    plaintextBytes
  ));
  const epk = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
  return {
    schema: "briar-courier-envelope-v1",
    message_id: toHex(randomBytes(16)),
    recipient_key_id: recipientKeyId,
    ephemeral_public_key_jwk: {
      kty: epk.kty,
      crv: epk.crv,
      x: epk.x,
      y: epk.y
    },
    hkdf_salt_b64u: b64uEncode(salt),
    aes_gcm_nonce_b64u: b64uEncode(nonce),
    ciphertext_b64u: b64uEncode(ciphertext)
  };
}

async function decryptActionEnvelope(identity, envelope) {
  if (!identity?.privateKey) throw new Error("CRYPTO_KEY_MISSING");
  if (envelope?.schema !== "briar-courier-envelope-v1") throw new Error("ENVELOPE_SCHEMA_REJECTED");
  if (envelope.recipient_key_id !== identity.key_id) throw new Error("RECIPIENT_MISMATCH");
  const epk = await importPublicJwk(envelope.ephemeral_public_key_jwk);
  const salt = b64uDecode(envelope.hkdf_salt_b64u);
  const nonce = b64uDecode(envelope.aes_gcm_nonce_b64u);
  const cipher = b64uDecode(envelope.ciphertext_b64u);
  const aes = await deriveActionAesKey(identity.privateKey, epk, salt);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      aes,
      cipher
    ));
  } catch {
    throw new Error("AUTHENTICATION_FAILED");
  }
}

async function selfTest() {
  requireCrypto();
  const device = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const keyId = await fingerprintPublicKey(device.publicKey);
  const plaintext = te.encode(JSON.stringify({
    schema: "briar-courier-self-test-v1",
    payload: "POCKET_RELAY_CRYPTO_GREEN"
  }));
  const identity = {
    key_id: keyId,
    publicKey: device.publicKey,
    privateKey: device.privateKey
  };

  const envelope = await encryptForDevice(device.publicKey, keyId, plaintext);
  const recovered = await decryptActionEnvelope(identity, envelope);
  const roundTrip = td.decode(recovered) === td.decode(plaintext);
  if (!roundTrip) throw new Error("CRYPTO_ROUND_TRIP_MISMATCH");

  const tampered = structuredClone(envelope);
  const bytes = b64uDecode(tampered.ciphertext_b64u);
  bytes[Math.floor(bytes.length / 2)] ^= 0x01;
  tampered.ciphertext_b64u = b64uEncode(bytes);

  let tamperRejected = false;
  try {
    await decryptActionEnvelope(identity, tampered);
  } catch (e) {
    tamperRejected = String(e.message || e) === "AUTHENTICATION_FAILED";
  }
  if (!tamperRejected) throw new Error("CRYPTO_TAMPER_NOT_REJECTED");

  return {
    result: "GREEN",
    round_trip: "GREEN",
    tamper_rejection: "GREEN",
    algorithm: "ECDH-P256/HKDF-SHA256/AES-256-GCM"
  };
}

window.BriarCourierCrypto = Object.freeze({
  supported: () => !!(globalThis.crypto?.subtle && globalThis.indexedDB),
  generateDeviceIdentity,
  loadDeviceIdentity,
  ensureDeviceIdentity,
  exportPublicPairingRecord,
  fingerprintPublicKey,
  prettyFingerprint,
  encryptForDevice,
  decryptActionEnvelope,
  selfTest,
  b64uEncode,
  b64uDecode
});
})();