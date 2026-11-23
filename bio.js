// Face ID / Touch ID unlock (0.10.4) with WebAuthn: a passkey made by the phone's platform authenticator,
// "userVerification: required". No server: the public key stays in IndexedDB and every unlock is checked here
// (origin, challenge, rpId hash, user-verified flag, ECDSA P-256 signature). The PIN always stays valid.
// It only opens the app's screen, like the PIN: the link keys are not derived from it.
import { b64 } from './link.js';

const subtle = crypto.subtle;
const enc = new TextEncoder();

export async function available() {
  try {
    return !!(window.PublicKeyCredential && navigator.credentials
      && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

/** Creates the passkey (shows Face ID). Must be called straight from a tap. Returns what to store. */
export async function register(rpId, origin) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({ publicKey: {
    rp: { id: rpId, name: 'Phylax Genitore' },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'Phylax Genitore', displayName: 'Genitore' },
    challenge,
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged', requireResidentKey: false },
    attestation: 'none',
    timeout: 60000,
  } });
  if (!cred) throw new Error('Nessuna credenziale');
  const r = cred.response;
  const client = JSON.parse(new TextDecoder().decode(r.clientDataJSON));
  if (client.type !== 'webauthn.create' || client.challenge !== b64(challenge) || client.origin !== origin) throw new Error('Risposta non valida');
  const att = cbor(new Uint8Array(r.attestationObject));
  const authData = att.authData;
  await checkAuthData(authData, rpId);
  let spki = null;
  if (typeof r.getPublicKey === 'function' && r.getPublicKeyAlgorithm && r.getPublicKeyAlgorithm() === -7) {
    const k = r.getPublicKey();
    if (k) spki = new Uint8Array(k);
  }
  if (!spki) spki = await spkiFromAuthData(authData);
  return { id: b64(new Uint8Array(cred.rawId)), spki: b64(spki), count: counter(authData), created: Date.now() };
}

/** Asks Face ID for the stored passkey and checks the answer. Resolves true only if everything matches. */
export async function unlock(stored, rpId, origin, unb64) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.get({ publicKey: {
    challenge, rpId, timeout: 60000, userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: unb64(stored.id) }],
  } });
  if (!cred || b64(new Uint8Array(cred.rawId)) !== stored.id) return { ok: false };
  const r = cred.response;
  return verifyAssertion(unb64(stored.spki), stored.count || 0, {
    authenticatorData: new Uint8Array(r.authenticatorData),
    clientDataJSON: new Uint8Array(r.clientDataJSON),
    signature: new Uint8Array(r.signature),
  }, challenge, rpId, origin);
}

/** Pure check of an assertion (also used by the Node test). Returns { ok, count }. */
export async function verifyAssertion(spki, lastCount, a, challenge, rpId, origin) {
  let client;
  try { client = JSON.parse(new TextDecoder().decode(a.clientDataJSON)); } catch { return { ok: false }; }
  if (client.type !== 'webauthn.get' || client.challenge !== b64(challenge) || client.origin !== origin || client.crossOrigin === true) return { ok: false };
  try { await checkAuthData(a.authenticatorData, rpId); } catch { return { ok: false }; }
  const count = counter(a.authenticatorData);
  if (count !== 0 && lastCount !== 0 && count <= lastCount) return { ok: false }; // cloned authenticator
  const key = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const hash = new Uint8Array(await subtle.digest('SHA-256', a.clientDataJSON));
  const data = concat(a.authenticatorData, hash);
  let raw;
  try { raw = derToRaw(a.signature); } catch { return { ok: false }; }
  const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, data);
  return { ok, count };
}

async function checkAuthData(ad, rpId) {
  if (!(ad instanceof Uint8Array) || ad.length < 37) throw new Error('authData');
  const want = new Uint8Array(await subtle.digest('SHA-256', enc.encode(rpId)));
  for (let i = 0; i < 32; i++) if (ad[i] !== want[i]) throw new Error('rpId');
  const flags = ad[32];
  if (!(flags & 0x01) || !(flags & 0x04)) throw new Error('Serve Face ID'); // user present + user verified
}
const counter = ad => ((ad[33] << 24) >>> 0) + (ad[34] << 16) + (ad[35] << 8) + ad[36];

async function spkiFromAuthData(ad) {
  if (!(ad[32] & 0x40)) throw new Error('Chiave assente');
  const len = (ad[53] << 8) | ad[54];
  const cose = cbor(ad.subarray(55 + len));
  if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) throw new Error('Chiave non supportata');
  const raw = concat(new Uint8Array([4]), cose.get(-2), cose.get(-3));
  const key = await subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  return new Uint8Array(await subtle.exportKey('spki', key));
}

/** DER ECDSA signature -> r||s (32 bytes each), as WebCrypto wants. */
export function derToRaw(der) {
  if (der[0] !== 0x30) throw new Error('firma');
  let i = 2;
  if (der[1] & 0x80) i = 2 + (der[1] & 0x7f);
  const out = new Uint8Array(64);
  for (let part = 0; part < 2; part++) {
    if (der[i] !== 0x02) throw new Error('firma');
    const len = der[i + 1], start = i + 2;
    let v = der.subarray(start, start + len);
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32) throw new Error('firma');
    out.set(v, part * 32 + 32 - v.length);
    i = start + len;
  }
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Minimal CBOR reader (enough for attestationObject and COSE keys). Maps with text keys become objects. */
export function cbor(bytes) {
  let p = 0;
  const uint = add => {
    if (add < 24) return add;
    const n = add === 24 ? 1 : add === 25 ? 2 : add === 26 ? 4 : add === 27 ? 8 : -1;
    if (n < 0 || p + n > bytes.length) throw new Error('CBOR');
    let v = 0;
    for (let k = 0; k < n; k++) v = v * 256 + bytes[p++];
    return v;
  };
  const item = depth => {
    if (depth > 8 || p >= bytes.length) throw new Error('CBOR');
    const b = bytes[p++], major = b >> 5, add = b & 31;
    if (major === 7) { if (add === 20) return false; if (add === 21) return true; if (add === 22) return null; throw new Error('CBOR'); }
    const v = uint(add);
    switch (major) {
      case 0: return v;
      case 1: return -1 - v;
      case 2: { if (p + v > bytes.length) throw new Error('CBOR'); const s = bytes.slice(p, p + v); p += v; return s; }
      case 3: { if (p + v > bytes.length) throw new Error('CBOR'); const s = new TextDecoder().decode(bytes.subarray(p, p + v)); p += v; return s; }
      case 4: { const a = []; for (let k = 0; k < v; k++) a.push(item(depth + 1)); return a; }
      case 5: {
        const m = new Map();
        for (let k = 0; k < v; k++) { const key = item(depth + 1); m.set(key, item(depth + 1)); }
        if ([...m.keys()].every(key => typeof key === 'string')) return Object.fromEntries(m);
        return m;
      }
      default: throw new Error('CBOR');
    }
  };
  return item(0);
}
