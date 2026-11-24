// Phylax Genitore — web app (PWA) for the parent's iPhone. Same protocol and look as the Android app.
// Stores on this device ONLY: the key pair (private key not extractable), topics, counters, PIN hash,
// last contact time. Since 0.15 also alerts, archive, reports and status, ENCRYPTED (AES-256-GCM) with a
// random data key that is itself stored only wrapped by a key derived from the PIN (PBKDF2, never the PIN
// itself) and, if Face ID is on, by a non-extractable key of this browser. At every opening what our mailbox
// still keeps (7 days, ciphertext only) is read again; already-seen messages are skipped by counter (0.17: no ntfy.sh).
import * as L from './link.js';
import * as Bio from './bio.js';
import * as QR from './qr.js';

const VERSION = '0.17';
const SILENT_MS = 60 * 60 * 1000;            // like LinkPolicy: warning after 1 hour without messages
const MAX_AGE_S = 24 * 60 * 60;              // reject messages published > 24 h after they were written (replays)
const LOCK_AFTER_MS = 5 * 60 * 1000;         // PIN again after 5 minutes in the background
const PBKDF2_ITERATIONS = 310000;
const MAX_ALERTS = 100, MAX_FRAGMENTS = 200, MAX_ARCHIVED_KEYS = 300;
const LINK_WINDOW_MS = 2 * 60 * 1000;        // an alert within 2 minutes of a report's opening belongs to it

// ---------- IndexedDB (key/value) ----------
const db = (() => {
  let handle;
  const open = () => handle || (handle = new Promise((res, rej) => {
    const r = indexedDB.open('tutela-genitore', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  }));
  const tx = async (mode, fn) => {
    const d = await open();
    return new Promise((res, rej) => {
      const t = d.transaction('kv', mode), req = fn(t.objectStore('kv'));
      t.oncomplete = () => res(req && req.result);
      t.onerror = () => rej(t.error);
    });
  };
  return {
    get: k => tx('readonly', s => s.get(k)),
    set: (k, v) => tx('readwrite', s => s.put(v, k)),
    del: k => tx('readwrite', s => s.delete(k)),
  };
})();

// ---------- State ----------
const S = {
  pair: null,        // { topic, notifyTopic, priv (CryptoKey, not extractable), pub (Uint8Array), code, created }
  child: null,       // { spki (b64), verification }
  keys: null,
  pin: null, unlocked: false, hiddenAt: 0, pinFails: 0, pinWaitUntil: 0,
  bio: null, bioAvailable: false, bioAuto: true, bioBusy: false, // Face ID (WebAuthn passkey), 0.10.4
  sent: 0, seenMax: 0, lastSeenSaved: 0,
  alerts: [], reports: new Map(), state: null, detail: '', lastSeen: 0, lastStatus: 0,
  lastC2P: 0, lastP2C: 0,
  online: false, loaded: false, error: '', outbox: [], outboxWait: 5000,
  showCode: true, archived: new Map(), showArchived: false,
  pushState: null, subscribed: false, pushSentEndpoint: null, pushError: '',
  dk: null, dkRaw: null, ready: false, // 0.15: data key once unlocked; ready = saved copy loaded, may connect
};

// ---------- Small helpers ----------
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : String(kid));
  return e; // data is always set as text, never as HTML
}
const pad = n => String(n).padStart(2, '0');
function hm(t) {
  const d = new Date(t), now = new Date();
  const time = pad(d.getHours()) + ':' + pad(d.getMinutes());
  return d.toDateString() === now.toDateString() ? time : pad(d.getDate()) + '/' + pad(d.getMonth() + 1) + ' ' + time;
}
function ago(ms) { const m = Math.floor(ms / 60000); return m < 1 ? 'adesso' : m < 60 ? m + ' min fa' : Math.floor(m / 60) + ' h fa'; }
const spaced = v => v ? v.slice(0, 3) + ' ' + v.slice(3) : '';
let toastTimer;
function toast(text, ms = 2500) {
  const t = document.getElementById('toast');
  t.textContent = text; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}
async function copy(text, what) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const t = h('textarea', { readonly: true, class: 'offscreen' }); t.value = text;
    document.body.append(t); t.select(); document.execCommand('copy'); t.remove();
  }
  toast(what + ' copiato');
}
const route = () => (location.hash || '#/').slice(2);
const go = r => { location.hash = '#/' + r; };

// ---------- PIN (PBKDF2-SHA256 via WebCrypto) ----------
// 512 bits from one PBKDF2: the first 256 are the stored check value (same as before 0.15, so old PINs keep
// working), the second 256 are never stored and wrap the data key (0.15).
async function pinBits(pin, salt, iterations) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 512));
  return { hash: bits.slice(0, 32), kek: bits.slice(32) };
}
async function setPin(pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pinBits(pin, salt, PBKDF2_ITERATIONS);
  // len: lets the lock screen unlock by itself at the last digit (no "Sblocca" tap).
  S.pin = { salt: L.b64(salt), hash: L.b64(bits.hash), iterations: PBKDF2_ITERATIONS, len: pin.length };
  await db.set('pin', S.pin);
  await Vault.withPin(bits.kek); // new PIN (or changed): the data key is wrapped again with it
  bits.kek.fill(0);
}
/** Returns the PIN-derived wrapping bits if the PIN is right, else null. */
async function checkPin(pin) {
  const bits = await pinBits(pin, L.unb64(S.pin.salt), S.pin.iterations), want = L.unb64(S.pin.hash);
  let diff = bits.hash.length ^ want.length;
  for (let i = 0; i < bits.hash.length; i++) diff |= bits.hash[i] ^ want[i];
  if (diff !== 0) { bits.kek.fill(0); return null; }
  return bits.kek;
}

// ---------- 0.15: alerts saved on this phone, encrypted at rest ----------
// A random 256-bit data key encrypts the saved copy. On disk the data key exists only wrapped: with the
// PIN-derived bits (PBKDF2) and, if Face ID is on, with a non-extractable AES key of this browser. While the
// page is open it stays in memory (like the link keys), so a PIN change or turning Face ID on re-wraps it.
const Vault = (() => {
  const subtle = crypto.subtle, enc = new TextEncoder();
  const AAD = enc.encode('phylax-vault-1'), WRAP = enc.encode('phylax-dk-1');
  const gcm = raw => subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  async function seal(key, bytes, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return { iv: L.b64(iv), ct: L.b64(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, bytes))) };
  }
  async function unseal(key, box, aad) {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: L.unb64(box.iv), additionalData: aad }, key, L.unb64(box.ct)));
  }
  async function use(raw) { S.dkRaw = raw; S.dk = await gcm(raw); }
  const V = {
    /** After the right PIN, or a new PIN: opens the data key (or makes the first one) and wraps it with this PIN. */
    async withPin(kek) {
      const box = await db.get('dkPin');
      if (!S.dkRaw && box) { try { await use(await unseal(await gcm(kek), box, WRAP)); } catch { /* damaged: start over */ } }
      if (!S.dkRaw) { await db.del('vault'); await db.del('dkBio'); await use(crypto.getRandomValues(new Uint8Array(32))); }
      await db.set('dkPin', await seal(await gcm(kek), S.dkRaw, WRAP));
      if (S.bio && !await db.get('dkBio')) await V.addBio();
    },
    /** After Face ID: only the copy wrapped with this browser's key. False: nothing saved is readable this time. */
    async withBio() {
      try {
        const k = await db.get('bioKek'), box = await db.get('dkBio');
        if (k && box) { await use(await unseal(k, box, WRAP)); return true; }
      } catch { /* fall through */ }
      return false;
    },
    async addBio() {
      if (!S.dkRaw) return;
      let k = await db.get('bioKek');
      if (!k) { k = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); await db.set('bioKek', k); }
      await db.set('dkBio', await seal(k, S.dkRaw, WRAP));
    },
    async forgetBio() { await db.del('dkBio'); await db.del('bioKek'); },
    async save() {
      if (!S.dk) return;
      const snap = { v: 1, alerts: S.alerts, reports: [...S.reports.values()], state: S.state, detail: S.detail,
        lastStatus: S.lastStatus, lastSeen: S.lastSeen, lastC2P: S.lastC2P, lastP2C: S.lastP2C };
      await db.set('vault', await seal(S.dk, enc.encode(JSON.stringify(snap)), AAD));
    },
    /** Puts the saved copy into S. Counters come with it, so re-reading the mailbox does not add the same messages twice. */
    async load() {
      const box = S.dk && await db.get('vault');
      if (!box) return false;
      let snap;
      try { snap = JSON.parse(new TextDecoder().decode(await unseal(S.dk, box, AAD))); } catch { return false; }
      if (!snap || snap.v !== 1) return false;
      S.alerts = (snap.alerts || []).slice(0, MAX_ALERTS);
      S.reports = new Map((snap.reports || []).map(r => [r.id, r]));
      S.state = snap.state || null; S.detail = snap.detail || ''; S.lastStatus = snap.lastStatus || 0;
      S.lastSeen = Math.max(S.lastSeen, snap.lastSeen || 0);
      S.lastC2P = snap.lastC2P || 0; S.lastP2C = snap.lastP2C || 0;
      return true;
    },
  };
  return V;
})();
let saveTimer = null;
function saveSoon() { clearTimeout(saveTimer); saveTimer = setTimeout(() => Vault.save().catch(() => {}), 400); }

// ---------- Received data (same rules as ParentStore.java) ----------
// ---------- Archive (local only: a key per alert in IndexedDB, nothing is sent) ----------
const norm = t => (t || '').toLowerCase().replace(/\[tutela-test\]/g, '').replace(/\s+/g, ' ').trim();
function alertKey(a) {
  let x = 0;
  for (const ch of a.category + '|' + a.text) x = (x * 31 + ch.codePointAt(0)) >>> 0;
  return a.time + ':' + x.toString(36);
}
/** Same rule as ParentStore.linked: near the report's opening, or its text is one of the report's messages. */
function linked(a, r) {
  if (Math.abs(a.time - r.opened) <= LINK_WINDOW_MS) return true;
  const t = norm(a.text);
  return r.fragments.some(f => { const x = norm(f.text); return x.length > 0 && (t.includes(x) || x.includes(t)); });
}
function setArchived(a, on) {
  a.archived = on;
  const k = alertKey(a);
  S.archived.delete(k); S.archived.set(k, on); // false = put back by the parent: a re-read closure won't archive it again
  while (S.archived.size > MAX_ARCHIVED_KEYS) S.archived.delete(S.archived.keys().next().value);
  db.set('archived', [...S.archived]).catch(() => {});
  saveSoon();
}
function closeLocally(id) {
  const r = S.reports.get(id);
  if (r) for (const a of S.alerts) if (!a.archived && S.archived.get(alertKey(a)) !== false && linked(a, r)) setArchived(a, true);
  S.reports.delete(id);
}

function resetData() {
  S.alerts = []; S.reports = new Map(); S.state = null; S.detail = ''; S.lastStatus = 0;
  S.lastC2P = 0; S.lastP2C = 0;
}
function apply(m, receivedAt) {
  S.lastSeen = Math.max(S.lastSeen, receivedAt);
  switch (m.type) {
    case 'ALERT':
      S.alerts.unshift({ high: m.level === L.LEVEL_HIGH, doubt: m.level === L.LEVEL_DOUBT, category: m.category, app: m.app, text: m.text, time: m.time });
      S.alerts[0].archived = S.archived.get(alertKey(S.alerts[0])) === true;
      S.alerts.length = Math.min(S.alerts.length, MAX_ALERTS);
      return 'ALERT';
    case 'CASE_OPEN':
      S.reports.set(m.caseId, { id: m.caseId, app: m.app, reason: m.category, opened: m.time, fragments: m.fragments.map(text => ({ text, time: m.time })) });
      return 'REPORT_OPENED';
    case 'CASE_FRAGMENTS': {
      let r = S.reports.get(m.caseId);
      if (!r) { r = { id: m.caseId, app: m.app, reason: m.category, opened: m.time, fragments: [] }; S.reports.set(m.caseId, r); }
      for (const text of m.fragments) r.fragments.push({ text, time: m.time });
      if (r.fragments.length > MAX_FRAGMENTS) r.fragments.splice(0, r.fragments.length - MAX_FRAGMENTS);
      return 'REPORT_UPDATED';
    }
    case 'STATUS': {
      if (m.time < S.lastStatus) return 'NONE';
      S.lastStatus = m.time;
      const changed = S.state !== m.state;
      S.state = m.state;
      if (!m.heartbeat || m.text) S.detail = m.text;
      return changed || !m.heartbeat ? 'STATUS' : 'NONE';
    }
    case 'PUSH':
      S.pushState = m.outcome === L.PUSH_ACTIVE ? 'ok' : m.outcome === L.PUSH_EXPIRED ? 'expired' : S.pushState;
      db.set('pushState', S.pushState).catch(() => {});
      return 'NONE';
    default: return 'NONE';
  }
}

async function ensureKeys() {
  if (S.keys || !S.child) return !!S.keys;
  S.keys = await L.derive(S.pair.priv, await L.importPublic(L.unb64(S.child.spki)), S.pair.topic);
  return true;
}

/** One mailbox message. Foreign, altered, replayed, too old: ignored. `live` = arrived now (not the first read). */
async function handle(ev, live) {
  let hd;
  try { hd = L.peek(ev.message); } catch { return; }
  try {
    if (hd.direction === L.C2P) {
      const childB64 = L.b64(hd.childKey);
      if (!S.child) {
        // First contact: trust this child key (TOFU) only if it decrypts; confirmed by the 6-digit code.
        const k = await L.derive(S.pair.priv, await L.importPublic(hd.childKey), S.pair.topic);
        await L.open(k.c2p, L.C2P, ev.message, 0);
        S.child = { spki: childB64, verification: k.verification };
        S.keys = k; S.showCode = false; // the code is no longer needed on screen
        await db.set('child', S.child);
        S.pushState = null; db.del('pushState').catch(() => {});
        if (S.subscribed) resendPush(true); // new pairing: hand the existing notification permission to the new child
      } else if (S.child.spki !== childB64) { S.error = 'Messaggio da un telefono non abbinato: ignorato.'; return; }
      await ensureKeys();
      const { header, plaintext } = await L.open(S.keys.c2p, L.C2P, ev.message, S.lastC2P);
      const m = L.decodeMessage(plaintext);
      if (ev.time - m.time / 1000 > MAX_AGE_S) return;
      S.lastC2P = header.counter;
      const what = apply(m, ev.time * 1000);
      saveSoon();
      const fresh = header.counter > S.seenMax;
      if (fresh) { S.seenMax = header.counter; db.set('seenMax', S.seenMax); }
      if (S.lastSeen - S.lastSeenSaved > 60000) { S.lastSeenSaved = S.lastSeen; db.set('lastSeen', S.lastSeen); }
      if (live && fresh) announce(what, m);
    } else if (hd.direction === L.P2C && await ensureKeys()) {
      // Our own "close report" (also from another device with this pairing): the report is gone.
      const { header, plaintext } = await L.open(S.keys.p2c, L.P2C, ev.message, S.lastP2C);
      S.lastP2C = header.counter;
      const m = L.decodeMessage(plaintext);
      if (m.type === 'CLOSE_CASE') { closeLocally(m.caseId); saveSoon(); }
    }
  } catch { /* not ours, altered or replayed */ }
  scheduleRender();
}

function announce(what, m) {
  if (what === 'NONE' || what === 'REPORT_UPDATED' && !m.fragments.length) return;
  const text = what === 'ALERT' ? 'Nuovo avviso' : what === 'REPORT_OPENED' ? 'Segnalazione aperta' :
    what === 'REPORT_UPDATED' ? 'Nuovo messaggio nella segnalazione' : m.state === 'INTERRUPTED' ? 'Protezione interrotta' : 'Stato aggiornato';
  toast(text);
  try { navigator.setAppBadge && navigator.setAppBadge(); } catch { /* not supported */ }
  // Content-free system notification (like the Android lock screen): details only inside the app, after the PIN.
  if ('Notification' in window && Notification.permission === 'granted' && document.visibilityState !== 'visible') {
    navigator.serviceWorker?.ready.then(reg => reg.showNotification('Phylax Genitore', { body: text, tag: 'tutela', icon: 'icons/icon-192.png' })).catch(() => {});
  }
}

// ---------- 0.17: our mailbox (kept 7 days) is the only path; ntfy.sh is no longer used ----------
let mboxBusy = false, fromStart = true, queue = Promise.resolve();
function enqueue(fn) { queue = queue.then(fn, fn); return queue; }
/**
 * Runs inside enqueue(). Reads both mailboxes of the pair (the child's messages and our own closures, also those
 * sent from another device) after the last position, oldest first, through handle(). The first read after an
 * opening starts from the beginning (7 days): the counters skip what the saved copy already has, and without a
 * readable saved copy the state is rebuilt from the mailbox.
 */
async function pollMailbox() {
  if (!S.pair || !S.ready || mboxBusy) return;
  mboxBusy = true;
  const topic = S.pair.topic;
  try {
    const boxes = [await L.mailboxName(topic, 'c2p'), await L.mailboxName(topic, 'p2c')];
    const since = fromStart ? [0, 0] : [S.mboxSince || 0, S.mboxSinceP2c || 0];
    const got = [];
    for (let b = 0; b < 2; b++) {
      for (let page = 0; page < 10; page++) {
        const r = await L.mailboxPoll(boxes[b], since[b]);
        for (const m of r.messages) got.push(m);
        since[b] = r.next;
        if (r.messages.length < 100) break;
      }
    }
    if (!S.pair || S.pair.topic !== topic) return; // new pairing meanwhile
    got.sort((x, y) => x.t - y.t || x.id - y.id);
    for (const m of got) await handle({ time: Math.floor(m.t / 1000), message: m.msg }, S.loaded);
    S.mboxSince = since[0]; S.mboxSinceP2c = since[1];
    fromStart = false; S.loaded = true;
    S.online = true; if (S.error === MBOX_DOWN) S.error = '';
  } catch { S.online = false; S.error = MBOX_DOWN; } finally { mboxBusy = false; }
  scheduleRender();
}
const MBOX_DOWN = 'Casella non raggiungibile: nuovo tentativo tra poco.';
function connect() { if (S.pair && S.ready) enqueue(() => pollMailbox()); }
// Every 15 s while the app is on screen (in the background the iPhone wakes it by Web Push, straight from the child).
setInterval(() => { if (document.visibilityState === 'visible') connect(); scheduleRender(); }, 15000);

async function closeReport(id, outcome) {
  if (!await ensureKeys()) return;
  S.sent = L.nextCounter(S.sent, Date.now());
  await db.set('sent', S.sent);
  const wire = await L.seal(S.keys.p2c, L.P2C, null, S.sent, L.closeMessage(Date.now(), id, outcome));
  closeLocally(id);
  saveSoon();
  S.outbox.push(wire);
  await db.set('outbox', S.outbox);
  drain();
  toast(outcome === L.OUTCOME_OK ? 'Chiusa: tutto ok' : 'Chiusa: intervieni tu');
  go('');
}
let draining = false;
async function drain() {
  if (draining || !S.pair) return;
  draining = true;
  while (S.outbox.length) {
    try {
      // 0.17: to the child's mailbox only (ntfy.sh is no longer used).
      if (!await ensureKeys()) break;
      await L.mailboxPost(await L.mailboxName(S.pair.topic, 'p2c'), S.keys.mailboxAuth, S.outbox[0]);
      S.outbox.shift(); S.outboxWait = 5000; await db.set('outbox', S.outbox);
    }
    catch {
      S.error = 'Chiusura non ancora inviata (rete): nuovo tentativo tra ' + Math.round(S.outboxWait / 1000) + ' s.';
      setTimeout(drain, S.outboxWait); S.outboxWait = Math.min(S.outboxWait * 2, 300000);
      break;
    }
  }
  draining = false;
  scheduleRender();
}

// ---------- Web Push (0.10.3): the child's phone rings this web app directly, no server, no extra app ----------
const standalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
/** VAPID key pair for this phone; made in advance so the tap goes straight to the permission prompt. */
async function vapid() {
  let v = await db.get('vapid');
  if (!v) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    v = { priv: L.b64(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey))),
          pub: L.b64(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))) };
    await db.set('vapid', v);
  }
  return v;
}
async function currentSubscription() {
  if (!pushSupported()) return null;
  const reg = await navigator.serviceWorker.getRegistration();
  return reg ? reg.pushManager.getSubscription() : null;
}
/** Sends endpoint + keys + VAPID private key to the child, sealed in the E2E channel (never in clear). */
async function sendPushSetup(sub, v) {
  if (!await ensureKeys()) return false;
  const j = sub.toJSON();
  const msg = L.encodeMessage({ type: 'PUSH', time: Date.now(),
    fragments: [j.endpoint, j.keys.p256dh, j.keys.auth, v.priv, v.pub, location.origin + '/'] });
  S.sent = L.nextCounter(S.sent, Date.now());
  await db.set('sent', S.sent);
  S.outbox.push(await L.seal(S.keys.p2c, L.P2C, null, S.sent, msg));
  await db.set('outbox', S.outbox);
  S.pushSentEndpoint = j.endpoint; await db.set('pushSent', j.endpoint);
  S.pushState = 'waiting';
  drain();
  return true;
}
/** Called from the button: the permission prompt must come first, straight from the tap. */
function enablePush() {
  S.pushError = '';
  Notification.requestPermission().then(async perm => {
    if (perm !== 'granted') { S.pushError = 'Notifiche non consentite. Per attivarle: Impostazioni › Notifiche › Phylax Genitore.'; render(); return; }
    try {
      const v = await vapid();
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      const key = sub && sub.options && sub.options.applicationServerKey ? L.b64(new Uint8Array(sub.options.applicationServerKey)) : null;
      if (sub && key && key !== v.pub) { await sub.unsubscribe(); sub = null; }
      if (!sub || S.pushState === 'expired') {
        if (sub) await sub.unsubscribe();
        sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: L.unb64(v.pub) });
      }
      S.subscribed = true;
      if (!S.child) { S.pushError = 'Notifiche consentite: si attivano appena il telefono di tuo figlio è abbinato.'; render(); return; }
      await sendPushSetup(sub, v);
      toast('Notifiche attivate');
    } catch (e) { S.pushError = 'Attivazione non riuscita (' + (e && e.name || 'errore') + '). Riprova.'; }
    render();
  });
}
/** Re-sends the setup when the child is new or the browser changed the endpoint. */
async function resendPush(force) {
  try {
    const sub = await currentSubscription();
    S.subscribed = !!sub;
    if (!sub || !S.child) return;
    if (force || sub.endpoint !== S.pushSentEndpoint) await sendPushSetup(sub, await vapid());
  } catch { /* retried at the next opening */ }
}

async function newPairing() {
  const kp = await L.newKeyPair();
  const topic = L.newTopic();
  const pub = await L.spki(kp.publicKey);
  // v1 code: no separate notification topic any more, notifications come by Web Push (0.10.3).
  S.pair = { topic, notifyTopic: null, priv: kp.privateKey, pub, code: L.pairingCode(topic, pub), created: Date.now() };
  S.child = null; S.keys = null; S.pushState = null; S.pushSentEndpoint = null; S.sent = 0; S.seenMax = 0; S.lastSeen = 0; S.outbox = []; S.loaded = false; S.showCode = true;
  resetData();
  await db.set('pair', S.pair);
  S.archived = new Map();
  S.mboxSince = 0; S.mboxSinceP2c = 0; fromStart = true; S.online = false;
  for (const k of ['child', 'sent', 'seenMax', 'lastSeen', 'outbox', 'archived', 'pushSent', 'pushState', 'vault', 'mboxSince']) await db.del(k);
  clearTimeout(saveTimer);
  connect();
}

// ---------- Rendering ----------
let renderPending = false;
function scheduleRender() {
  if (renderPending) return;
  renderPending = true;
  requestAnimationFrame(() => { renderPending = false; render(); });
}
const shield = () => h('img', { class: 'logo', src: 'icons/shield.svg', alt: '' });
function header(title, back) {
  return h('div', { class: 'head' },
    back ? h('button', { class: 'back', 'aria-label': 'Indietro', onclick: () => go('') }, '‹') : shield(),
    h('h1', {}, title));
}

function render() {
  const app = document.getElementById('app');
  const r = route();
  // Do not redraw a page while the user is typing in it.
  if (app.dataset.page && app.dataset.page === pageKey(r) && app.querySelector('input:focus')) return;
  app.dataset.page = pageKey(r);
  app.replaceChildren(...page(r));
}
function pageKey(r) { return !S.pin ? 'setpin' : !S.unlocked ? 'lock' : r.split('/')[0] || 'home'; }
function page(r) {
  if (!S.pin) return pinPage('Scegli un PIN', 'Protegge gli avvisi su questo telefono. Almeno 6 cifre.', true);
  if (!S.unlocked) return pinPage('Phylax Genitore', 'Inserisci il PIN.', false);
  const [name, arg] = r.split('/');
  if (name === 'report') return reportPage(Number(arg));
  if (name === 'pair') return pairPage();
  if (name === 'notify') return notifyPage();
  if (name === 'pin') return pinPage('Cambia PIN', 'Nuovo PIN, almeno 6 cifre.', true, true);
  return homePage();
}

function pinPage(title, sub, choosing, change) {
  const lockLen = !choosing && S.pin && S.pin.len ? S.pin.len : 0;
  const input = h('input', { class: 'pin-input', type: 'password', inputmode: 'numeric', autocomplete: 'off', maxlength: String(lockLen || 12), 'aria-label': 'PIN' });
  const again = choosing ? h('input', { class: 'pin-input', type: 'password', inputmode: 'numeric', autocomplete: 'off', maxlength: '12', placeholder: 'ripeti', 'aria-label': 'Ripeti il PIN' }) : null;
  const err = h('p', { class: 'err' });
  let checking = false;
  const wrong = text => {
    input.value = ''; err.textContent = text;
    input.classList.remove('shake'); void input.offsetWidth; input.classList.add('shake');
    try { navigator.vibrate && navigator.vibrate(180); } catch { /* not supported (iPhone) */ }
  };
  // probe: PIN saved before 0.10.4, length unknown: try silently from the 6th digit on, never count it as an error.
  const submit = async probe => {
    const pin = input.value.trim();
    if (choosing) {
      if (!/^\d{6,12}$/.test(pin)) { err.textContent = 'Usa da 6 a 12 cifre.'; return; }
      if (pin !== again.value.trim()) { err.textContent = 'I due PIN non coincidono.'; return; }
      btn.disabled = true;
      await setPin(pin); S.unlocked = true; toast(change ? 'PIN cambiato' : 'PIN impostato');
      if (change) go(''); else afterUnlock();
      return;
    }
    if (checking || !pin) return;
    if (Date.now() < S.pinWaitUntil) { wrong('Troppi tentativi: riprova tra ' + Math.ceil((S.pinWaitUntil - Date.now()) / 1000) + ' s.'); return; }
    checking = true; btn.disabled = true;
    const kek = await checkPin(pin);
    if (kek) {
      if (!S.pin.len) { S.pin.len = pin.length; db.set('pin', S.pin).catch(() => {}); }
      try { await Vault.withPin(kek); } catch { /* storage problem: this time nothing is saved */ }
      kek.fill(0);
      checking = false; btn.disabled = false;
      S.unlocked = true; S.pinFails = 0; afterUnlock(); return;
    }
    checking = false; btn.disabled = false;
    if (probe === true) { if (input.value !== pin && input.value.length >= 6) submit(true); return; }
    S.pinFails++;
    if (S.pinFails >= 5) { S.pinWaitUntil = Date.now() + 30000 * Math.pow(2, S.pinFails - 5); }
    wrong('PIN errato.');
  };
  const btn = h('button', { class: 'btn primary', hidden: lockLen > 0, onclick: () => submit(false) }, choosing ? 'Salva PIN' : 'Sblocca');
  const onKey = e => { if (e.key === 'Enter') submit(false); };
  input.addEventListener('keydown', onKey); again && again.addEventListener('keydown', onKey);
  if (!choosing) {
    // Unlocks by itself at the last digit: no button to press.
    input.addEventListener('input', () => {
      const digits = input.value.replace(/\D/g, '');
      if (digits !== input.value) input.value = digits;
      if (digits.length) err.textContent = '';
      if (lockLen) { if (digits.length === lockLen) submit(false); }
      else if (digits.length >= 6) submit(true);
    });
  }
  const bio = !choosing && S.bio
    ? h('button', { class: 'btn ghost', onclick: () => bioUnlock(true) }, 'Sblocca con Face ID') : null;
  if (bio && S.bioAuto) { S.bioAuto = false; setTimeout(() => bioUnlock(false), 300); }
  else setTimeout(() => input.focus(), 50);
  return [h('div', { class: 'lock' },
    change ? header(title, true) : h('div', { class: 'head' }, shield(), h('h1', {}, title)),
    h('p', { class: 'sub' }, sub), input, again, err, btn, bio,
    change ? null : h('p', { class: 'caption center' }, 'Il PIN resta solo su questo telefono (PBKDF2). Se lo dimentichi: abbina di nuovo.'))];
}

/** After the PIN or Face ID: the saved copy (if this unlock could open it) is loaded once, then the mailbox. */
async function afterUnlock() {
  if (S.dk && !S.vaultLoaded) {
    S.vaultLoaded = true;
    const live = S.ready ? { alerts: S.alerts, reports: S.reports, state: S.state, detail: S.detail, lastStatus: S.lastStatus, c2p: S.lastC2P, p2c: S.lastP2C } : null;
    const got = await Vault.load().catch(() => false);
    if (got && live) {
      // Face ID first (no saved copy readable), PIN now: keep both what was saved and what arrived meanwhile.
      const seen = new Set(S.alerts.map(alertKey));
      for (const a of live.alerts) if (!seen.has(alertKey(a))) S.alerts.push(a);
      S.alerts.sort((x, y) => y.time - x.time); S.alerts.length = Math.min(S.alerts.length, MAX_ALERTS);
      for (const [id, r] of live.reports) S.reports.set(id, r);
      if (live.lastStatus >= S.lastStatus) { S.state = live.state; S.detail = live.detail; S.lastStatus = live.lastStatus; }
      S.lastC2P = Math.max(S.lastC2P, live.c2p); S.lastP2C = Math.max(S.lastP2C, live.p2c);
    }
    if (got) saveSoon();
  }
  S.ready = true;
  render(); connect();
}

// ---------- Face ID (WebAuthn passkey on this iPhone; the PIN always works too) ----------
async function bioUnlock(manual) {
  if (!S.bio || S.bioBusy || S.unlocked) return;
  S.bioBusy = true;
  try {
    const r = await Bio.unlock(S.bio, location.hostname, location.origin, L.unb64);
    if (r.ok) {
      if (r.count) { S.bio.count = r.count; db.set('bio', S.bio).catch(() => {}); }
      if (!S.dk && !await Vault.withBio().catch(() => false)) {
        // First Face ID opening after the 0.15 update: the data key is wrapped only after one PIN entry.
        toast('Per salvare gli avvisi su questo telefono entra una volta con il PIN', 6000);
      }
      S.unlocked = true; S.pinFails = 0; afterUnlock(); return;
    }
    if (manual) toast('Face ID non verificato: usa il PIN');
  } catch (e) {
    if (manual) toast(e && e.name === 'NotAllowedError' ? 'Face ID annullato: usa il PIN' : 'Face ID non disponibile: usa il PIN');
  } finally { S.bioBusy = false; }
}
async function toggleBio() {
  if (S.bio) {
    if (!confirm('Disattivare lo sblocco con Face ID? Il PIN resta valido.')) return;
    S.bio = null; await db.del('bio'); await Vault.forgetBio();
    toast('Face ID disattivato'); render(); return;
  }
  try {
    const rec = await Bio.register(location.hostname, location.origin); // straight from the tap: Face ID shows now
    S.bio = rec; await db.set('bio', rec);
    await Vault.addBio().catch(() => {}); // Face ID can open the saved alerts too
    toast('Face ID attivato'); render();
  } catch (e) {
    toast(e && e.name === 'NotAllowedError' ? 'Attivazione annullata' : 'Face ID non attivato' + (e && e.message ? ': ' + e.message : ''));
  }
}

function statusCard() {
  const now = Date.now();
  let cls = '', title, line, action = 'Abbinamento e codice di verifica';
  if (!S.pair) { title = 'Non abbinato'; line = 'Abbina il telefono di tuo figlio con un codice.'; action = 'Abbina'; }
  else if (!S.child) { title = 'In attesa del telefono di tuo figlio'; line = 'Incolla il codice in Phylax sul suo telefono › Telefono del genitore.'; }
  else if (S.loaded && now - S.lastSeen > SILENT_MS) { cls = 'broken'; title = 'Non risponde da più di 1 ora'; line = 'Può essere spento, senza rete, o l\'app è stata fermata o disinstallata.'; }
  else if (!S.state) { title = 'Abbinato'; line = S.loaded ? 'Nessun messaggio nelle ultime ore.' : 'Lettura degli avvisi cifrati…'; }
  else {
    if (S.state === 'INTERRUPTED') { cls = 'broken'; title = 'Protezione interrotta'; }
    else if (S.state === 'STOPPED') { cls = 'idle'; title = 'Protezione fermata'; }
    else title = 'Protezione attiva';
    line = (S.detail ? S.detail + ' · ' : '') + 'ultimo contatto ' + ago(now - S.lastSeen);
  }
  return h('div', { class: 'status ' + cls },
    h('h2', {}, title), h('p', {}, line),
    h('button', { class: 'btn white', onclick: () => go('pair') }, action));
}

function homePage() {
  const out = [header('Phylax Genitore'), h('p', { class: 'sub' }, 'Avvisi cifrati dal telefono di tuo figlio.'), statusCard()];
  if (S.pair) {
    out.push(h('p', { class: 'caption' }, h('span', { class: 'dot' + (S.online ? ' on' : '') }),
      S.online ? 'In ascolto (casella cifrata)' : S.loaded ? 'Non collegato: nuovo tentativo…' : 'Collegamento alla casella…', S.error ? ' · ' + S.error : ''));
  }
  out.push(h('div', { class: 'section' }, 'Segnalazioni aperte'));
  const reports = [...S.reports.values()];
  if (!reports.length) out.push(h('p', { class: 'caption' }, 'Nessuna segnalazione aperta.'));
  for (const r of reports) {
    out.push(h('div', { class: 'card row', role: 'button', tabindex: '0', onclick: () => go('report/' + r.id) },
      h('div', { class: 'ico' }, '✉'),
      h('div', { class: 'txt' }, h('div', { class: 't' }, r.reason + ' · ' + r.app),
        h('div', { class: 's' }, r.fragments.length + ' messaggi · aperta alle ' + hm(r.opened))),
      h('div', { class: 'chev' }, '›')));
  }
  out.push(h('div', { class: 'section' }, 'Avvisi'));
  const active = S.alerts.filter(a => !a.archived), archived = S.alerts.filter(a => a.archived);
  if (!active.length) out.push(h('div', { class: 'card empty' }, h('b', {}, 'Nessun avviso.'), 'Gli avvisi arrivano cifrati e restano salvati, cifrati, solo su questo telefono.'));
  for (const a of active) out.push(alertCard(a, false));
  if (archived.length) {
    out.push(h('button', { class: 'toggle', 'aria-expanded': String(S.showArchived), onclick: () => { S.showArchived = !S.showArchived; render(); } },
      'Archiviati (' + archived.length + ') ' + (S.showArchived ? '▴' : '▾')));
    if (S.showArchived) for (const a of archived) out.push(alertCard(a, true));
  }
  out.push(h('div', { class: 'section' }, 'Notifiche'));
  out.push(navRow('🔔', 'Notifiche', pushLine(), () => go('notify'), true));
  out.push(h('div', { class: 'section' }, 'Sicurezza'));
  out.push(navRow('#', 'Cambia PIN', 'Serve il PIN attuale (già inserito)', () => go('pin')));
  if (S.bio || S.bioAvailable) {
    out.push(navRow('☺', 'Sblocca con Face ID', S.bio ? 'Attivo · tocca per disattivarlo · il PIN resta valido'
      : 'Disattivo · tocca per attivarlo · il PIN resta sempre valido', toggleBio));
  }
  out.push(navRow('🔒', 'Blocca ora', S.bio ? 'Chiede Face ID o il PIN' : 'Chiede di nuovo il PIN', () => { S.unlocked = false; render(); }));
  out.push(h('p', { class: 'caption center' }, 'Versione web ' + VERSION + ' · consegna tramite '
    + 'la nostra casella cifrata (Cloudflare, tiene i messaggi 7 giorni)'
    + ', solo testo cifrato · qui restano salvati cifrati (chiave protetta dal PIN o da Face ID) · solo prove con messaggi inventati [TUTELA-TEST]'));
  return out;
}
function alertCard(a, archived) {
  return h('div', { class: 'card alert' + (archived ? ' archived' : '') },
    h('div', { class: 'alert-top' }, h('span', { class: 'chip ' + (a.high ? 'danger' : a.doubt ? 'doubt' : 'warning') }, a.high ? 'Rischio alto' : a.doubt ? 'Dubbio · da guardare' : 'Da verificare'),
      h('span', { class: 'time' }, hm(a.time))),
    h('h3', {}, a.category), h('p', { class: 'meta' }, a.app), h('div', { class: 'quote' }, a.text),
    a.category === 'Possibile foto intima' ? h('p', { class: 'caption' }, '📷 Solo testo: l\'immagine resta sul telefono di tuo figlio e non viene mai inviata. Non chiedere di vederla o di inoltrartela.') : null,
    h('button', { class: 'link', onclick: () => { setArchived(a, !archived); toast(archived ? 'Rimesso tra gli avvisi' : 'Avviso archiviato'); render(); } },
      archived ? 'Rimetti tra gli avvisi' : 'Archivia'));
}
function navRow(icon, title, sub, onclick, indigo) {
  return h('div', { class: 'card row', role: 'button', tabindex: '0', onclick },
    h('div', { class: 'ico' + (indigo ? ' indigo' : '') }, icon),
    h('div', { class: 'txt' }, h('div', { class: 't' }, title), h('div', { class: 's' }, sub)),
    h('div', { class: 'chev' }, '›'));
}

function reportPage(id) {
  const r = S.reports.get(id);
  const out = [header('Segnalazione aperta', true), h('p', { class: 'sub' }, 'Solo questa chat, solo dall\'avviso in poi.')];
  if (!r) { out.push(h('div', { class: 'card empty' }, h('b', {}, 'Segnalazione chiusa o non più disponibile.'))); return out; }
  out.push(h('div', { class: 'card' },
    h('h3', { class: 'card-title' }, r.reason),
    h('p', { class: 'meta' }, r.app + ' · aperta alle ' + hm(r.opened)),
    r.fragments.map(f => h('div', { class: 'bubble' }, f.text, h('span', { class: 'bt' }, hm(f.time))))));
  const language = r.reason === 'Lingua o codice non riconosciuto'; // 0.13: same command as "Tutto ok"
  out.push(h('button', { class: 'btn outline', onclick: e => { e.target.disabled = true; closeReport(id, L.OUTCOME_OK); } }, language ? 'Questa lingua va bene · chiudi e cancella' : 'Tutto ok · chiudi e cancella'));
  if (language) out.push(h('p', { class: 'caption' }, 'Per questa chat Phylax non avviserà più solo per la lingua; le parole a rischio continuano a far partire gli avvisi.'));
  out.push(h('button', { class: 'btn primary', onclick: e => { e.target.disabled = true; closeReport(id, L.OUTCOME_INTERVENE); } }, 'Intervengo · chiudi e cancella'));
  out.push(h('p', { class: 'caption' }, 'Chiudere cancella la segnalazione qui e, al prossimo controllo (entro circa 30 secondi), anche sul telefono di tuo figlio.'));
  return out;
}

function pairPage() {
  const out = [header('Abbinamento', true)];
  if (!S.pair) {
    out.push(h('p', { class: 'sub' }, 'Crea un codice e incollalo sul telefono di tuo figlio.'));
    out.push(h('div', { class: 'card' },
      h('ol', { class: 'steps' },
        h('li', {}, 'Tocca «Crea codice di abbinamento»: compare un QR.'),
        h('li', {}, 'Sul telefono di tuo figlio: Phylax › Telefono del genitore › PIN genitore › «Fotografa il QR» (oppure copia e incolla il codice) › Abbina.'),
        h('li', {}, 'Confrontate il codice di verifica a 6 cifre: deve essere uguale sui due telefoni.')),
      h('button', { class: 'btn primary', onclick: async e => { e.target.disabled = true; await newPairing(); render(); } }, 'Crea codice di abbinamento')));
    return out;
  }
  if (S.child) {
    out.push(h('p', { class: 'sub' }, 'Telefono di tuo figlio collegato.'));
    out.push(h('div', { class: 'card' },
      h('p', { class: 'meta' }, 'Codice di verifica'),
      h('div', { class: 'verify' }, spaced(S.child.verification)),
      h('p', { class: 'caption' }, 'Deve essere uguale a quello mostrato sul telefono di tuo figlio. Se è diverso, qualcuno si è messo in mezzo: crea un nuovo abbinamento.')));
  } else {
    out.push(h('p', { class: 'sub' }, 'In attesa del telefono di tuo figlio.'));
  }
  const box = h('div', { class: 'code-box' + (S.showCode ? '' : ' masked') }, S.pair.code);
  if (!S.child) {
    // 0.15: QR of the same code, made here (qr.js); the SVG contains only fixed characters and numbers.
    const qr = h('div', { class: 'qr' });
    try { qr.innerHTML = QR.svg(QR.encode(S.pair.code, 'M')); } catch { qr.textContent = 'QR non disponibile: usa il codice.'; }
    out.push(h('div', { class: 'card' },
      h('p', { class: 'card-head' }, 'Inquadra questo QR dal telefono di tuo figlio'),
      qr,
      h('p', { class: 'caption' }, 'Sul suo telefono: Phylax › PIN › Telefono del genitore › «Fotografa il QR». Poi tocca «Abbina questo telefono».')));
  }
  out.push(h('div', { class: 'card' },
    h('p', { class: 'meta' }, 'Codice di abbinamento (contiene solo la chiave pubblica e i due topic)'),
    box,
    h('div', { class: 'gap' }),
    h('button', { class: 'btn primary', onclick: () => copy(S.pair.code, 'Codice') }, 'Copia'),
    h('button', { class: 'btn ghost', onclick: () => { S.showCode = !S.showCode; render(); } }, S.showCode ? 'Nascondi codice' : 'Mostra codice'),
    S.child ? null : h('ol', { class: 'steps' },
      h('li', {}, 'Sul telefono di tuo figlio: Phylax › Telefono del genitore › PIN genitore.'),
      h('li', {}, 'Fotografa il QR qui sopra (o incolla il codice) e tocca Abbina.'),
      h('li', {}, 'Qui comparirà il codice di verifica a 6 cifre.'))));
  out.push(h('button', { class: 'btn danger', onclick: async () => {
    if (!confirm('Nuovo abbinamento? Il telefono di tuo figlio non potrà più raggiungere questa app finché non incolli il nuovo codice.')) return;
    await newPairing(); render();
  } }, 'Nuovo abbinamento'));
  return out;
}

function pushLine() {
  if (!pushSupported()) return 'Non disponibili in questo browser';
  if (!standalone()) return 'Aggiungi l\'app alla schermata Home per attivarle';
  if (S.pushState === 'expired') return 'Da riattivare: tocca qui';
  if (S.subscribed && S.pushState === 'ok') return 'Attive · solo «Nuovo avviso da Phylax: apri l\'app»';
  if (S.subscribed && S.child) return 'In attesa del telefono di tuo figlio…';
  return 'Spente: tocca qui per attivarle';
}
function notifyPage() {
  const out = [header('Notifiche', true),
    h('p', { class: 'sub' }, 'Il telefono di tuo figlio fa suonare questo iPhone. La notifica dice solo «Nuovo avviso da Phylax: apri l\'app»: il contenuto lo vedi solo qui, con il PIN.')];
  if (!pushSupported() || !standalone()) {
    out.push(h('div', { class: 'card' },
      h('p', { class: 'card-head' }, 'Prima aggiungi l\'app alla schermata Home'),
      h('ol', { class: 'steps' },
        h('li', {}, 'Apri questa pagina in Safari.'),
        h('li', {}, 'Tocca Condividi (il quadrato con la freccia) › «Aggiungi alla schermata Home».'),
        h('li', {}, 'Apri Phylax Genitore dall\'icona sulla Home e torna qui: comparirà «Attiva notifiche».')),
      h('p', { class: 'caption' }, 'Su iPhone le notifiche delle app web funzionano solo così (iOS 16.4 o successivo).')));
    return out;
  }
  const state = S.pushState === 'expired' ? 'Notifiche da riattivare: il permesso è scaduto o è stato tolto.'
    : S.subscribed && S.pushState === 'ok' ? 'Notifiche attive. Il telefono di tuo figlio ha confermato.'
    : S.subscribed && S.child ? 'Permesso dato. In attesa della conferma del telefono di tuo figlio (entro circa 30 secondi).'
    : 'Notifiche spente.';
  out.push(h('div', { class: 'card' },
    h('p', { class: 'card-head' }, state),
    S.pushError ? h('p', { class: 'err' }, S.pushError) : null,
    (!S.subscribed || S.pushState === 'expired' || !S.pushState)
      ? h('button', { class: 'btn primary', onclick: enablePush }, S.pushState === 'expired' ? 'Riattiva notifiche' : 'Attiva notifiche')
      : h('button', { class: 'btn ghost', onclick: () => { resendPush(true); toast('Richiesta inviata'); render(); } }, 'Invia di nuovo al telefono di tuo figlio')));
  out.push(h('div', { class: 'card' },
    h('p', { class: 'card-head' }, 'Privacy'),
    h('p', { class: 'caption' }, 'Le notifiche non passano dalla nostra casella e non serve un account. Il servizio notifiche di Apple riceve solo una notifica cifrata con un testo fisso, senza nomi, chat o categorie. L\'indirizzo delle notifiche passa al telefono di tuo figlio solo cifrato.')));
  return out;
}

// ---------- Start ----------
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') { S.hiddenAt = Date.now(); return; }
  if (S.hiddenAt && Date.now() - S.hiddenAt > LOCK_AFTER_MS && S.unlocked) { S.unlocked = false; S.bioAuto = true; }
  try { navigator.clearAppBadge && navigator.clearAppBadge(); } catch { /* not supported */ }
  connect();
  scheduleRender();
});
window.addEventListener('hashchange', () => { render(); window.scrollTo(0, 0); });
window.addEventListener('online', () => { drain(); connect(); });

(async function start() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  try {
    S.pin = await db.get('pin') || null;
    S.bio = await db.get('bio') || null;
    S.pair = await db.get('pair') || null;
    S.child = await db.get('child') || null;
    S.showCode = !S.child;
    S.sent = await db.get('sent') || 0;
    S.seenMax = await db.get('seenMax') || 0;
    S.lastSeen = S.lastSeenSaved = await db.get('lastSeen') || 0;
    S.outbox = await db.get('outbox') || [];
    S.archived = new Map(await db.get('archived') || []);
    S.pushSentEndpoint = await db.get('pushSent') || null;
    S.pushState = await db.get('pushState') || null;
  } catch {
    document.getElementById('app').replaceChildren(h('p', { class: 'caption center' }, 'Memoria del browser non disponibile (navigazione privata?).'));
    return;
  }
  render();
  Bio.available().then(v => { S.bioAvailable = v; scheduleRender(); });
  if (S.outbox.length) drain();
  if (pushSupported() && standalone()) { vapid().catch(() => {}); resendPush(false).then(scheduleRender); }
})();
