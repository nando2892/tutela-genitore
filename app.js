// Phylax Genitore — web app (PWA) for the parent's iPhone. Same protocol and look as the Android app.
// Stores on this device ONLY: the key pair (private key not extractable), topics, counters, PIN hash,
// last contact time. Since 0.15 also alerts, archive, reports and status, ENCRYPTED (AES-256-GCM) with a
// random data key that is itself stored only wrapped by a key derived from the PIN (PBKDF2, never the PIN
// itself) and, if Face ID is on, by a non-extractable key of this browser. At every opening what our mailbox
// still keeps (7 days, ciphertext only) is read again; already-seen messages are skipped by counter (0.17: no ntfy.sh).
import * as L from './link.js';
import * as Bio from './bio.js';
import * as QR from './qr.js';

const VERSION = '0.28';
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

// 0.26: more children in one app. Slot 0 keeps the keys of earlier versions; slot n puts 'c<n>:' in front.
const MAX_CHILDREN = 4;
const CHILD_KEYS = ['pair', 'child', 'sent', 'seenMax', 'lastSeen', 'outbox', 'archived', 'pushSent', 'pushState', 'vault', 'mboxSince'];
const K = (name, slot = S.slot) => slot ? 'c' + slot + ':' + name : name;

// ---------- State ----------
const S = {
  slot: 0, family: { slots: [], names: {}, current: 0 }, others: {}, // 0.26: children (see K)
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
  // 0.22: screen time. usage = today's minutes from the child; rules = what we last sent; requests = «15 minuti in più?»
  week: null, usage: { day: '', time: 0, apps: [] }, rules: { version: 0, night: null, school: null, limits: [], sites: [], allow: [], deny: [], places: [] }, requests: [], editRules: null,
  // 0.24: «Dov'è?»: only the last answer (no history), the last «arrivato»/«uscito» per safe place.
  where: { spot: null, asked: 0, none: '', noneTime: 0, n: 0, places: {} }, placeForm: false,
  battery: { pct: -1, time: 0 }, // 0.25: last battery level from the child's heartbeat
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
      if (!S.dkRaw) { for (let n = 0; n < MAX_CHILDREN; n++) await db.del(K('vault', n)); await db.del('dkBio'); await use(crypto.getRandomValues(new Uint8Array(32))); }
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
        lastStatus: S.lastStatus, lastSeen: S.lastSeen, lastC2P: S.lastC2P, lastP2C: S.lastP2C,
        usage: S.usage, week: S.week, rules: S.rules, requests: S.requests, where: S.where, battery: S.battery };
      await db.set(K('vault'), await seal(S.dk, enc.encode(JSON.stringify(snap)), AAD));
    },
    /** Puts the saved copy into S. Counters come with it, so re-reading the mailbox does not add the same messages twice. */
    async load() {
      const box = S.dk && await db.get(K('vault'));
      if (!box) return false;
      let snap;
      try { snap = JSON.parse(new TextDecoder().decode(await unseal(S.dk, box, AAD))); } catch { return false; }
      if (!snap || snap.v !== 1) return false;
      S.alerts = (snap.alerts || []).slice(0, MAX_ALERTS);
      S.reports = new Map((snap.reports || []).map(r => [r.id, r]));
      S.state = snap.state || null; S.detail = snap.detail || ''; S.lastStatus = snap.lastStatus || 0;
      S.lastSeen = Math.max(S.lastSeen, snap.lastSeen || 0);
      S.lastC2P = snap.lastC2P || 0; S.lastP2C = snap.lastP2C || 0;
      if (snap.usage) S.usage = snap.usage;
      S.week = snap.week || null;
      if (snap.rules) S.rules = snap.rules;
      S.requests = snap.requests || [];
      if (snap.where) S.where = snap.where;
      if (snap.battery) S.battery = snap.battery;
      if (!S.rules.places) S.rules.places = [];
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
  db.set(K('archived'), [...S.archived]).catch(() => {});
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
  S.usage = { day: '', time: 0, apps: [] }; S.week = null; S.rules = { version: 0, night: null, school: null, limits: [], sites: [], allow: [], deny: [], places: [] }; S.requests = [];
  S.where = { spot: null, asked: 0, none: '', noneTime: 0, n: 0, places: {} }; S.battery = { pct: -1, time: 0 };
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
      if ((m.outcome === L.BATTERY_INFO || m.outcome === L.BATTERY_LOW) && m.level >= 0 && m.level <= 100) S.battery = { pct: m.level, time: m.time };
      const changed = S.state !== m.state;
      S.state = m.state;
      if (!m.heartbeat || m.text) S.detail = m.text;
      if (m.outcome === L.BATTERY_LOW) return 'BATTERY_LOW';
      return changed || !m.heartbeat ? 'STATUS' : 'NONE';
    }
    case 'WEEK': // 0.28: the summary of the week, sent on Sunday evening
      if (S.week && (m.time < S.week.time || m.text < S.week.weekStart)) return 'NONE';
      S.week = { weekStart: m.text, time: m.time, lines: (m.fragments || []).slice(0, 60) };
      return 'NONE';
    case 'USAGE':
      if (m.time < S.usage.time) return 'NONE';
      S.usage = { day: m.text, time: m.time, apps: L.parseUsage(m.fragments) };
      return 'NONE';
    // 0.26: what the other parent decided, echoed by the child's phone to every parent.
    case 'RULES':
      if (m.caseId > S.rules.version) S.rules = L.parseRules(m.caseId, m.fragments);
      return 'NONE';
    case 'CLOSE_CASE':
      closeLocally(m.caseId);
      return 'NONE';
    case 'EXTRA':
      if (m.outcome !== L.EXTRA_ASK) { S.requests = S.requests.filter(r => r.pkg !== m.text); return 'NONE'; }
      if (!m.text) return 'NONE';
      S.requests = [{ pkg: m.text, label: m.app, minutes: m.caseId, time: m.time }, ...S.requests.filter(r => r.pkg !== m.text)].slice(0, 20);
      return 'EXTRA';
    case 'LOCATION': {
      const w = S.where;
      if (m.outcome === L.LOC_HERE) {
        const spot = L.parseWhere(m.text);
        if (!spot || (w.spot && m.time < w.spot.received)) return 'NONE';
        w.spot = { ...spot, received: m.time }; w.asked = 0; w.none = '';
        return 'LOCATION';
      }
      if (m.outcome === L.LOC_NONE) { w.none = m.text; w.noneTime = m.time; w.asked = 0; return 'LOCATION_NONE'; }
      if (m.outcome === L.LOC_PLACE && m.app) {
        const old = w.places[m.app];
        if (old && old.time > m.time) return 'NONE';
        w.places[m.app] = { arrived: m.level === 1, time: m.time };
        return 'PLACE';
      }
      return 'NONE';
    }
    case 'PUSH':
      S.pushState = m.outcome === L.PUSH_ACTIVE ? 'ok' : m.outcome === L.PUSH_EXPIRED ? 'expired' : S.pushState;
      db.set(K('pushState'), S.pushState).catch(() => {});
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
        await db.set(K('child'), S.child);
        S.pushState = null; db.del(K('pushState')).catch(() => {});
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
      if (fresh) { S.seenMax = header.counter; db.set(K('seenMax'), S.seenMax); }
      if (S.lastSeen - S.lastSeenSaved > 60000) { S.lastSeenSaved = S.lastSeen; db.set(K('lastSeen'), S.lastSeen); }
      if (live && fresh) announce(what, m);
    } else if (hd.direction === L.P2C && await ensureKeys()) {
      // Our own "close report" (also from another device with this pairing): the report is gone.
      const { header, plaintext } = await L.open(S.keys.p2c, L.P2C, ev.message, S.lastP2C);
      S.lastP2C = header.counter;
      const m = L.decodeMessage(plaintext);
      if (m.type === 'CLOSE_CASE') { closeLocally(m.caseId); saveSoon(); }
      // 0.22: our own rules and answers (also from another device of the parent).
      if (m.type === 'RULES' && m.caseId > S.rules.version) { S.rules = L.parseRules(m.caseId, m.fragments); saveSoon(); }
      if (m.type === 'EXTRA' && m.outcome !== L.EXTRA_ASK) { S.requests = S.requests.filter(r => r.pkg !== m.text); saveSoon(); }
      // 0.24: «Dov'è?» asked from here or from another device of the parent.
      if (m.type === 'LOCATION' && m.outcome === L.LOC_ASK) {
        S.where.n = Math.max(S.where.n, m.caseId);
        if (!S.where.spot || m.time > S.where.spot.received) S.where.asked = Math.max(S.where.asked, m.time);
        saveSoon();
      }
    }
  } catch { /* not ours, altered or replayed */ }
  scheduleRender();
}

function announce(what, m) {
  if (what === 'NONE' || what === 'REPORT_UPDATED' && !m.fragments.length) return;
  const text = what === 'EXTRA' ? 'Tuo figlio chiede ' + m.caseId + ' minuti in più' :
    what === 'ALERT' && m.category === L.CAT_SOS ? 'SOS da tuo figlio' :
    what === 'BATTERY_LOW' ? 'Batteria quasi scarica sul telefono di tuo figlio (' + m.level + '%)' :
    what === 'LOCATION' ? 'Posizione di tuo figlio arrivata' : what === 'LOCATION_NONE' ? 'Posizione non disponibile' :
    what === 'PLACE' ? (m.level === 1 ? 'Arrivato: ' : 'Uscito: ') + m.app : what === 'ALERT' ? 'Nuovo avviso' : what === 'REPORT_OPENED' ? 'Segnalazione aperta' :
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
// 0.28: fewer requests (Cloudflare bills by request). On screen: every 30 s, every 10 s for 3 minutes after sending
// something to the child (answers come quickly), and at once when a Web Push arrives (the service worker tells us).
let lastCommand = 0, lastPoll = 0;
setInterval(() => {
  const fast = Date.now() - lastCommand < 180000 || (S.pair && !S.child); // pairing: the child's hello comes soon
  if (document.visibilityState === 'visible' && Date.now() - lastPoll >= (fast ? 9500 : 29500)) { lastPoll = Date.now(); connect(); }
  scheduleRender();
}, 5000);
if ('serviceWorker' in navigator) navigator.serviceWorker.addEventListener('message', e => { if (e.data === 'phylax-push') { lastPoll = Date.now(); connect(); } });

/** Seals one command for the child (p2c), keeps it in the outbox until the mailbox takes it. */
async function sendToChild(plain) {
  lastCommand = Date.now();
  if (!await ensureKeys()) return false;
  S.sent = L.nextCounter(S.sent, Date.now());
  await db.set(K('sent'), S.sent);
  S.outbox.push(await L.seal(S.keys.p2c, L.P2C, null, S.sent, plain));
  await db.set(K('outbox'), S.outbox);
  drain();
  return true;
}
async function closeReport(id, outcome) {
  if (!await sendToChild(L.closeMessage(Date.now(), id, outcome))) return;
  closeLocally(id);
  saveSoon();
  toast(outcome === L.OUTCOME_OK ? 'Chiusa: tutto ok' : 'Chiusa: intervieni tu');
  go('');
}
let draining = false;
async function drain() {
  if (draining || !S.pair) return;
  draining = true;
  const slot = S.slot;
  while (S.outbox.length && slot === S.slot) {
    try {
      // 0.17: to the child's mailbox only (ntfy.sh is no longer used).
      if (!await ensureKeys()) break;
      await L.mailboxPost(await L.mailboxName(S.pair.topic, 'p2c'), S.keys.mailboxAuth, S.outbox[0]);
      S.outbox.shift(); S.outboxWait = 5000; await db.set(K('outbox'), S.outbox);
    }
    catch {
      S.error = 'Comando non ancora inviato (rete): nuovo tentativo tra ' + Math.round(S.outboxWait / 1000) + ' s.';
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
  await db.set(K('sent'), S.sent);
  S.outbox.push(await L.seal(S.keys.p2c, L.P2C, null, S.sent, msg));
  await db.set(K('outbox'), S.outbox);
  S.pushSentEndpoint = j.endpoint; await db.set(K('pushSent'), j.endpoint);
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

// ---------- 0.26: children ----------
/** Puts one child's saved keys and counters into S (the received data comes from its vault, see selectChild). */
async function loadChild() {
  S.pair = await db.get(K('pair')) || null;
  S.child = await db.get(K('child')) || null;
  S.showCode = !S.child;
  S.keys = null;
  S.sent = await db.get(K('sent')) || 0;
  S.seenMax = await db.get(K('seenMax')) || 0;
  S.lastSeen = S.lastSeenSaved = await db.get(K('lastSeen')) || 0;
  S.outbox = await db.get(K('outbox')) || []; S.outboxWait = 5000;
  S.archived = new Map(await db.get(K('archived')) || []);
  S.pushSentEndpoint = await db.get(K('pushSent')) || null;
  S.pushState = await db.get(K('pushState')) || null;
  S.mboxSince = 0; S.mboxSinceP2c = 0; fromStart = true; S.loaded = false; S.online = false; S.error = '';
  S.showArchived = false; S.editRules = null; S.placeForm = false;
}
const childName = slot => (S.family.names[slot] || '').trim() || 'Figlio ' + ((S.family.slots.indexOf(slot) + 1) || S.family.slots.length + 1);
async function selectChild(slot) {
  if (slot === S.slot) return;
  await enqueue(async () => {
    clearTimeout(saveTimer);
    if (S.slot >= 0) await Vault.save().catch(() => {});
    S.slot = slot; S.family.current = slot;
    if (S.peekSince) delete S.peekSince[slot];
    if (S.peekFresh) delete S.peekFresh[slot];
    delete S.others[slot];
    await db.set('family', S.family);
    await loadChild();
    resetData();
    if (S.dk) await Vault.load().catch(() => false);
  });
  render(); connect();
  if (S.outbox.length) drain();
  resendPush(false).then(scheduleRender);
  peekOthers();
}
async function addChild() {
  let free = -1;
  for (let n = 0; n < MAX_CHILDREN && free < 0; n++) if (!S.family.slots.includes(n)) free = n;
  if (free < 0) { toast('Al massimo ' + MAX_CHILDREN + ' figli in questa app.'); return; }
  const name = prompt('Come si chiama? (solo per distinguere i figli in questa app)', '');
  await selectChild(free);
  if (name && name.trim()) { S.family.names[free] = name.trim().slice(0, 20); await db.set('family', S.family); }
  await newPairing();
  go('pair');
}
async function renameChild() {
  const name = prompt('Nome da mostrare per questo figlio (resta su questo telefono)', childName(S.slot));
  if (name === null) return;
  S.family.names[S.slot] = name.trim().slice(0, 20);
  await db.set('family', S.family);
  render();
}
async function removeChild() {
  if (!confirm('Togliere ' + childName(S.slot) + '? Si cancellano il collegamento e i suoi avvisi da questo telefono. Sul telefono del ragazzo scollega poi questo genitore.')) return;
  const gone = S.slot;
  await enqueue(async () => {
    for (const k of CHILD_KEYS) await db.del(K(k, gone));
    S.family.slots = S.family.slots.filter(n => n !== gone);
    delete S.family.names[gone]; delete S.others[gone];
    await db.set('family', S.family);
  });
  const next = S.family.slots.length ? S.family.slots[0] : 0;
  S.slot = -1; // forces the switch, also to slot 0 when it was the one removed
  await selectChild(next);
  go('');
}
/**
 * The other children: how many alerts to look at (saved ones still open + important new ones in their mailbox),
 * without touching what is on screen. Only a number for the chips; their data is read when you switch to them.
 */
let peeking = false;
async function peekOthers() {
  if (peeking || !S.dk || !S.ready) return;
  peeking = true;
  try {
    for (const slot of S.family.slots) {
      if (slot === S.slot) continue;
      const pair = await db.get(K('pair', slot)), child = await db.get(K('child', slot));
      if (!pair || !child) { S.others[slot] = 0; continue; }
      let saved = 0, last = 0;
      const box = await db.get(K('vault', slot));
      if (box) try {
        const snap = JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: L.unb64(box.iv), additionalData: new TextEncoder().encode('phylax-vault-1') }, S.dk, L.unb64(box.ct))));
        saved = (snap.alerts || []).filter(a => !a.archived).length + (snap.reports || []).length + (snap.requests || []).length;
        last = snap.lastC2P || 0;
      } catch { /* unreadable: count only new ones */ }
      const keys = await L.derive(pair.priv, await L.importPublic(L.unb64(child.spki)), pair.topic);
      const p = S.peekSince || (S.peekSince = {});
      let since = p[slot] || 0, fresh = 0;
      const name = await L.mailboxName(pair.topic, 'c2p');
      for (let page = 0; page < 10; page++) {
        const r = await L.mailboxPoll(name, since);
        for (const m of r.messages) {
          try {
            const { header, plaintext } = await L.open(keys.c2p, L.C2P, m.msg, last);
            const msg = L.decodeMessage(plaintext);
            if (header.counter > last && (msg.type === 'ALERT' || msg.type === 'CASE_OPEN' || (msg.type === 'EXTRA' && msg.outcome === L.EXTRA_ASK))) fresh++;
          } catch { /* old or not ours */ }
        }
        since = r.next;
        if (r.messages.length < 100) break;
      }
      const f = S.peekFresh || (S.peekFresh = {});
      f[slot] = (p[slot] ? f[slot] || 0 : 0) + fresh;
      S.others[slot] = saved + f[slot];
      p[slot] = since;
    }
  } catch { /* offline: try again later */ } finally { peeking = false; }
  scheduleRender();
}
setInterval(() => { if (document.visibilityState === 'visible' && S.unlocked) peekOthers(); }, 60000);

/** Chips with the children's names under the title; nothing with a single child. */
function childBar() {
  const slots = [...S.family.slots];
  if (!slots.includes(S.slot) && S.pair) slots.push(S.slot);
  if (slots.length < 2) return null;
  return h('div', { class: 'kids', role: 'tablist', 'aria-label': 'Figli' },
    ...slots.map(n => {
      const c = n === S.slot ? 0 : S.others[n] || 0;
      return h('button', { class: 'kid' + (n === S.slot ? ' on' : ''), role: 'tab', 'aria-selected': String(n === S.slot), onclick: () => selectChild(n) },
        childName(n), c ? h('span', { class: 'badge' }, String(c)) : null);
    }),
    S.family.slots.length < MAX_CHILDREN ? h('button', { class: 'kid add', 'aria-label': 'Aggiungi un figlio', onclick: addChild }, '+') : null);
}

async function newPairing() {
  const kp = await L.newKeyPair();
  const topic = L.newTopic();
  const pub = await L.spki(kp.publicKey);
  // v1 code: no separate notification topic any more, notifications come by Web Push (0.10.3).
  S.pair = { topic, notifyTopic: null, priv: kp.privateKey, pub, code: L.pairingCode(topic, pub), created: Date.now() };
  S.child = null; S.keys = null; S.pushState = null; S.pushSentEndpoint = null; S.sent = 0; S.seenMax = 0; S.lastSeen = 0; S.outbox = []; S.loaded = false; S.showCode = true;
  resetData();
  await db.set(K('pair'), S.pair);
  S.archived = new Map();
  S.mboxSince = 0; S.mboxSinceP2c = 0; fromStart = true; S.online = false;
  for (const k of ['child', 'sent', 'seenMax', 'lastSeen', 'outbox', 'archived', 'pushSent', 'pushState', 'vault', 'mboxSince']) await db.del(K(k));
  if (!S.family.slots.includes(S.slot)) { S.family.slots.push(S.slot); S.family.slots.sort(); await db.set('family', S.family); }
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
const shield = () => h('img', { class: 'logo', src: 'icons/mark.svg', alt: '' });
// "Phylax …" titles show the brand wordmark: lowercase "phylax" in Baloo 2 ExtraBold, then the rest plain.
const titleEl = title => title.startsWith('Phylax')
  ? h('h1', { class: 'wordmark', 'aria-label': title }, h('span', { class: 'word' }, 'phylax'),
      title.length > 6 ? h('span', { class: 'rest' }, title.slice(6).trim().toLowerCase()) : null)
  : h('h1', {}, title);
function header(title, back) {
  return h('div', { class: 'head' },
    back != null && back !== false ? h('button', { class: 'back', 'aria-label': 'Indietro', onclick: () => go(back === true ? '' : back) }, '‹') : shield(),
    titleEl(title));
}
// 0.21: three tabs at the bottom (Avvisi / Figlio / Impostazioni); technical details only under Impostazioni › Avanzate.
const TAB_ICONS = {
  alerts: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a6 6 0 0 0-6 6v3.6L4.3 15.5A1 1 0 0 0 5.2 17h13.6a1 1 0 0 0 .9-1.5L18 12.6V9a6 6 0 0 0-6-6Zm-2.4 15.5a2.5 2.5 0 0 0 4.8 0Z"/></svg>',
  child: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 2.5h8A2.5 2.5 0 0 1 18.5 5v14a2.5 2.5 0 0 1-2.5 2.5H8A2.5 2.5 0 0 1 5.5 19V5A2.5 2.5 0 0 1 8 2.5Zm0 2a.5.5 0 0 0-.5.5v14a.5.5 0 0 0 .5.5h8a.5.5 0 0 0 .5-.5V5a.5.5 0 0 0-.5-.5Zm4 12a1.25 1.25 0 1 1 0 2.5 1.25 1.25 0 0 1 0-2.5Z"/></svg>',
  settings: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.3 2h3.4l.5 2.6c.6.2 1.2.5 1.7.9l2.5-.9 1.7 2.9-2 1.8a7 7 0 0 1 0 1.9l2 1.8-1.7 2.9-2.5-.9c-.5.4-1.1.7-1.7.9l-.5 2.6h-3.4l-.5-2.6c-.6-.2-1.2-.5-1.7-.9l-2.5.9-1.7-2.9 2-1.8a7 7 0 0 1 0-1.9l-2-1.8 1.7-2.9 2.5.9c.5-.4 1.1-.7 1.7-.9ZM12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7Z"/></svg>',
};
function tabBar(current) {
  const tab = (key, route, label) => {
    const ico = h('span', { class: 'tab-ico' }); ico.innerHTML = TAB_ICONS[key]; // fixed SVG written here, no data
    const badge = key === 'alerts' && activeCount() ? h('span', { class: 'badge' }, String(activeCount())) : null;
    return h('button', { class: 'tab' + (current === key ? ' on' : ''), 'aria-current': current === key ? 'page' : null, onclick: () => go(route) }, ico, badge, h('span', {}, label));
  };
  return h('nav', { class: 'tabbar', 'aria-label': 'Menu' }, tab('alerts', '', 'Avvisi'), tab('child', 'child', 'Figlio'), tab('settings', 'settings', 'Impostazioni'));
}
const activeCount = () => S.alerts.filter(a => !a.archived).length + S.reports.size + S.requests.length;

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
  if (name === 'advanced') return advancedPage();
  if (name === 'time') return timePage();
  if (name === 'sites') return sitesPage();
  if (name === 'week') return weekPage();
  if (name === 'talk') return talkPage(arg ? decodeURIComponent(arg) : null);
  if (name === 'child') return [...childPage(), tabBar('child')];
  if (name === 'settings') return [...settingsPage(), tabBar('settings')];
  return [...homePage(), tabBar('alerts')];
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
    change ? header(title, 'settings') : h('div', { class: 'head' }, shield(), titleEl(title)),
    h('p', { class: 'sub' }, sub), input, again, err, btn, bio,
    change ? null : h('p', { class: 'caption center' }, 'Il PIN resta solo su questo telefono. Se lo dimentichi, dovrai collegare di nuovo il telefono di tuo figlio.'))];
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
  setTimeout(peekOthers, 3000);
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

/** Plain-language state of the child's phone: { cls, title, line } (no technical words). */
function childState() {
  const now = Date.now();
  if (!S.pair) return { cls: 'idle', title: 'Telefono non collegato', line: 'Collega il telefono di tuo figlio per ricevere gli avvisi.' };
  if (!S.child) return { cls: 'idle', title: 'In attesa del telefono di tuo figlio', line: 'Fai inquadrare il QR dal suo telefono per finire il collegamento.' };
  if (S.loaded && now - S.lastSeen > SILENT_MS && S.battery.pct >= 0 && S.battery.pct <= 10)
    return { cls: 'idle', title: 'Probabilmente spento: batteria scarica', line: 'L\'ultima volta la batteria era al ' + S.battery.pct + '% (' + ago(now - S.battery.time) + ').' };
  if (S.loaded && now - S.lastSeen > SILENT_MS) return { cls: 'broken', title: 'Non risponde da più di 1 ora', line: 'Può essere spento o senza rete, oppure l\'app è stata fermata o tolta.' };
  if (!S.state) return { cls: '', title: 'Collegato', line: S.loaded ? 'Nessuna notizia nelle ultime ore.' : 'Sto leggendo gli avvisi…' };
  const last = 'ultimo contatto ' + ago(now - S.lastSeen) + (S.battery.pct >= 0 ? ' · batteria ' + S.battery.pct + '%' : '');
  const detail = S.detail && !S.detail.startsWith("Batteria") ? S.detail : ""; // the battery is shown once
  if (S.state === 'INTERRUPTED') return { cls: 'broken', title: 'Protezione interrotta', line: (detail ? detail + " · " : "") + last };
  if (S.state === 'STOPPED') return { cls: 'idle', title: 'Protezione in pausa', line: (detail ? detail + " · " : "") + last };
  return { cls: '', title: 'Protezione attiva', line: (detail ? detail + " · " : "") + last };
}

/** Home summary: "Tutto ok" or "N avvisi da guardare", with the owl. */
function summaryCard() {
  const st = childState(), n = activeCount();
  const urgent = S.alerts.some(a => !a.archived && a.high);
  let cls, title, line, btn = null;
  if (!S.pair || !S.child) {
    cls = 'idle'; title = !S.pair ? 'Iniziamo' : 'Quasi fatto'; line = st.line;
    btn = h('button', { class: 'btn white', onclick: () => go('pair') }, !S.pair ? 'Abbina' : 'Mostra il QR');
  } else if (n) {
    cls = urgent ? 'urgent' : 'look';
    title = n === 1 ? '1 avviso da guardare' : n + ' avvisi da guardare';
    line = urgent ? 'C\'è almeno un avviso urgente: guardalo appena puoi.' : 'Guardali con calma quando hai un momento.';
  } else if (st.cls === 'broken') {
    cls = 'broken'; title = st.title; line = st.line;
    btn = h('button', { class: 'btn white', onclick: () => go('child') }, 'Cosa fare');
  } else {
    cls = ''; title = 'Tutto ok'; line = S.loaded || S.state ? 'Nessun avviso nuovo. ' + (S.lastSeen ? 'Ultimo contatto: ' + ago(Date.now() - S.lastSeen) + '.' : '') : 'Sto controllando se ci sono avvisi…';
  }
  return h('div', { class: 'status hero ' + cls },
    h('img', { class: 'hero-owl', src: 'icons/mark.svg', alt: '' }),
    h('div', { class: 'hero-txt' }, h('h2', {}, title), h('p', {}, line)), btn);
}

function homePage() {
  const out = [header('Phylax Genitore'), childBar(), summaryCard()];
  if (S.pair && !S.online && S.loaded) out.push(h('p', { class: 'caption' }, h('span', { class: 'dot' }), 'Senza collegamento a internet: riprovo da solo…'));
  if (S.requests.length) {
    out.push(h('div', { class: 'section' }, 'Richieste di tempo'));
    for (const r of S.requests) out.push(h('div', { class: 'card' },
      h('h3', { class: 'card-title' }, 'Chiede ' + r.minutes + ' minuti in più per ' + r.label),
      h('p', { class: 'meta' }, 'Alle ' + hm(r.time) + '. Il tempo deciso per oggi è finito.'),
      h('button', { class: 'btn primary', onclick: e => { e.target.disabled = true; answerExtra(r, true); } }, 'Sì, ' + r.minutes + ' minuti'),
      h('button', { class: 'btn ghost', onclick: e => { e.target.disabled = true; answerExtra(r, false); } }, 'No, per oggi basta')));
  }
  const reports = [...S.reports.values()];
  if (reports.length) {
    out.push(h('div', { class: 'section' }, 'Chat da controllare'));
    for (const r of reports) {
      out.push(h('div', { class: 'card row', role: 'button', tabindex: '0', onclick: () => go('report/' + r.id) },
        h('div', { class: 'ico warn' }, '!'),
        h('div', { class: 'txt' }, h('div', { class: 't' }, r.reason + ' · ' + r.app),
          h('div', { class: 's' }, r.fragments.length + (r.fragments.length === 1 ? ' messaggio' : ' messaggi') + ' · dalle ' + hm(r.opened))),
        h('div', { class: 'chev' }, '›')));
    }
  }
  const active = S.alerts.filter(a => !a.archived), archived = S.alerts.filter(a => a.archived);
  if (S.pair) out.push(h('div', { class: 'section' }, 'Avvisi'));
  if (S.pair && !active.length) out.push(h('div', { class: 'card empty' }, h('img', { class: 'empty-owl', src: 'icons/mark.svg', alt: '' }),
    h('b', {}, 'Nessun avviso da guardare'), 'Se succede qualcosa ti avvisiamo noi. Gli avvisi restano solo su questo telefono, protetti dal PIN.'));
  for (const a of active) out.push(alertCard(a, false));
  if (archived.length) {
    out.push(h('button', { class: 'toggle', 'aria-expanded': String(S.showArchived), onclick: () => { S.showArchived = !S.showArchived; render(); } },
      'Archiviati (' + archived.length + ') ' + (S.showArchived ? '▴' : '▾')));
    if (S.showArchived) for (const a of archived) out.push(alertCard(a, true));
  }
  return out;
}

function childPage() {
  const st = childState();
  const out = [header(S.family.slots.length > 1 ? childName(S.slot) : 'Figlio'), childBar(), h('div', { class: 'status ' + st.cls }, h('h2', {}, st.title), h('p', {}, st.line),
    h('button', { class: 'btn white', onclick: () => go('pair') }, !S.pair ? 'Abbina' : !S.child ? 'Mostra il QR' : 'Collegamento e codice di verifica'))];
  if (st.cls === 'broken') {
    out.push(h('div', { class: 'card' }, h('p', { class: 'card-head' }, 'Cosa fare'),
      h('ol', { class: 'steps' },
        h('li', {}, 'Controlla che il telefono di tuo figlio sia acceso e abbia internet.'),
        h('li', {}, 'Apri Phylax sul suo telefono: deve dire «Protezione attiva».'),
        h('li', {}, 'Se l\'app non c\'è più, parlane con lui: era un patto fatto insieme.'))));
  }
  out.push(h('div', { class: 'section' }, 'Dov\'è?'));
  out.push(whereCard());
  out.push(h('div', { class: 'section' }, 'Tempo di oggi'));
  out.push(usageCard());
  out.push(h('div', { class: 'section' }, 'La settimana'));
  const wk = S.week ? L.parseWeek(S.week.weekStart, S.week.lines) : null;
  out.push(navRow('📊', 'Resoconto della settimana', wk ? weekRange(wk.weekStart) + (wk.average >= 0 ? ' · in media ' + dur(wk.average) + ' al giorno' : '') : 'Arriva la domenica sera', () => go('week')));
  out.push(h('div', { class: 'section' }, 'Siti'));
  out.push(navRow('🌐', 'Filtro siti', sitesSummary(S.rules), () => { S.editRules = null; go('sites'); }, true));
  out.push(h('div', { class: 'section' }, 'Parlarne'));
  out.push(navRow('💬', 'Come parlarne con tuo figlio', 'Prima di installarlo, per età, quando arriva un avviso', () => go('talk')));
  out.push(h('div', { class: 'section' }, 'Cosa fa Phylax'));
  out.push(h('div', { class: 'card' },
    h('ul', { class: 'plain' },
      h('li', {}, 'Legge le chat solo sul telefono di tuo figlio, e solo per cercare segnali di pericolo.'),
      h('li', {}, 'A te arriva solo l\'avviso con un breve pezzo di testo, mai tutte le chat.'),
      h('li', {}, 'Le foto non arrivano mai: al massimo un avviso che ce n\'è una a rischio.'),
      h('li', {}, 'Foto o vocali «visualizza una volta»: ti segnala solo che è successo, non cosa contengono.'))));
  return out;
}

// ---------- 0.22: screen time ----------
const today = () => { const d = new Date(); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); };
const hhmm = m => pad(Math.floor(m / 60)) + ':' + pad(m % 60);
const dur = m => m < 60 ? m + ' min' : m % 60 === 0 ? (m / 60) + ' h' : Math.floor(m / 60) + ' h ' + (m % 60) + ' min';
const limitLabel = m => m < 0 ? 'Nessun limite' : m === 0 ? 'In pausa tutto il giorno' : dur(m) + ' al giorno';
const CHOICES = [-1, 15, 30, 45, 60, 90, 120, 180, 0];
// 0.27: school mode. Days as bits, Monday = 1 (as on the phone).
const DAYS = ['lun', 'mar', 'mer', 'gio', 'ven', 'sab', 'dom'];
const schoolDays = m => m === 31 ? 'lun–ven' : m === 63 ? 'lun–sab' : DAYS.filter((_, i) => m & (1 << i)).join(', ');
function rulesSummary(r) {
  const parts = [];
  if (r.night) parts.push('Notte ' + hhmm(r.night[0]) + '–' + hhmm(r.night[1]));
  if (r.school) parts.push('Scuola ' + schoolDays(r.school.days) + ' ' + hhmm(r.school.start) + '–' + hhmm(r.school.end));
  if (r.limits.length) parts.push(r.limits.length + (r.limits.length === 1 ? ' app con limite' : ' app con limite'));
  return parts.length ? parts.join(' · ') : 'Nessuna regola';
}
function usageCard() {
  const card = h('div', { class: 'card' });
  const apps = S.usage.day === today() ? S.usage.apps : [];
  if (!apps.length) {
    card.append(h('p', {}, 'Ancora nessun dato di oggi.'),
      h('p', { class: 'caption' }, 'Sul telefono di tuo figlio: Phylax › Configurazione › «Consenti accesso ai dati di utilizzo». I minuti arrivano al massimo una volta all\'ora.'));
  } else {
    const total = apps.reduce((n, a) => n + a.minutes, 0), max = Math.max(1, ...apps.map(a => a.minutes));
    card.append(h('h3', { class: 'card-title' }, 'In tutto ' + dur(total)));
    for (const a of apps.slice(0, 8)) {
      const lim = S.rules.limits.find(l => l.pkg === a.pkg);
      const over = lim && lim.minutes > 0 && a.minutes >= lim.minutes;
      const bar = h('div', { class: 'bar-fill' + (over ? ' over' : '') });
      bar.style.width = Math.max(3, Math.round(100 * Math.min(1, a.minutes / max))) + '%';
      card.append(h('div', { class: 'usage-row' }, h('span', { class: 'u-name' }, a.label),
        h('span', { class: 'u-min' }, dur(a.minutes) + (lim ? ' · ' + (lim.minutes === 0 ? 'in pausa' : 'limite ' + dur(lim.minutes)) : ''))),
        h('div', { class: 'bar' }, bar));
    }
    card.append(h('p', { class: 'caption' }, 'Aggiornato alle ' + hm(S.usage.time) + '.'));
  }
  card.append(h('p', { class: 'caption' }, rulesSummary(S.rules)),
    h('button', { class: 'btn primary', onclick: () => { S.editRules = null; go('time'); } }, 'Limiti, notte e scuola'));
  return card;
}
function timePage() {
  if (!S.editRules) S.editRules = JSON.parse(JSON.stringify(S.rules));
  const e = S.editRules;
  const out = [header('Limiti, notte e scuola', 'child'),
    h('p', { class: 'sub' }, 'Decidetelo insieme: a tempo finito tuo figlio può chiederti 15 minuti in più.')];
  out.push(h('div', { class: 'section' }, 'Orario notte'));
  const start = h('input', { type: 'time', class: 'time-input', value: hhmm(e.night ? e.night[0] : 1320), 'aria-label': 'Inizio notte' });
  const end = h('input', { type: 'time', class: 'time-input', value: hhmm(e.night ? e.night[1] : 420), 'aria-label': 'Fine notte' });
  const toMin = v => { const [a, b] = v.split(':').map(Number); return a * 60 + b; };
  const sync = () => { if (e.night) e.night = [toMin(start.value), toMin(end.value)]; };
  start.addEventListener('change', sync); end.addEventListener('change', sync);
  const toggle = h('input', { type: 'checkbox', checked: !!e.night, onchange: ev => { e.night = ev.target.checked ? [toMin(start.value), toMin(end.value)] : null; render(); } });
  out.push(h('div', { class: 'card' },
    h('label', { class: 'switch-row' }, toggle, h('span', {}, 'Di notte solo telefono, contatti e sveglia')),
    e.night ? h('div', { class: 'time-row' }, h('span', {}, 'Dalle'), start, h('span', {}, 'alle'), end) : h('p', { class: 'caption' }, 'Spento')));
  out.push(h('div', { class: 'section' }, 'Modalità scuola'));
  const sStart = h('input', { type: 'time', class: 'time-input', value: hhmm(e.school ? e.school.start : 480), 'aria-label': 'Inizio scuola' });
  const sEnd = h('input', { type: 'time', class: 'time-input', value: hhmm(e.school ? e.school.end : 780), 'aria-label': 'Fine scuola' });
  const sSync = () => {
    if (!e.school) return;
    const a = toMin(sStart.value), b = toMin(sEnd.value);
    if (b > a) { e.school.start = a; e.school.end = b; } else toast('La fine deve venire dopo l\'inizio');
  };
  sStart.addEventListener('change', sSync); sEnd.addEventListener('change', sSync);
  const sToggle = h('input', { type: 'checkbox', checked: !!e.school, onchange: ev => {
    e.school = ev.target.checked ? { days: 31, start: 480, end: 780 } : null; render(); } });
  const dayBox = e.school ? h('div', { class: 'days' }, DAYS.map((d, i) => h('label', { class: 'day' },
    h('input', { type: 'checkbox', checked: !!(e.school.days & (1 << i)), 'aria-label': d, onchange: ev => {
      const m = ev.target.checked ? e.school.days | (1 << i) : e.school.days & ~(1 << i);
      if (!m) { ev.target.checked = true; toast('Scegli almeno un giorno'); return; }
      e.school.days = m; } }), h('span', {}, d)))) : null;
  out.push(h('div', { class: 'card' },
    h('label', { class: 'switch-row' }, sToggle, h('span', {}, 'A scuola solo telefono, contatti e sveglia')),
    e.school ? dayBox : h('p', { class: 'caption' }, 'Spento'),
    e.school ? h('div', { class: 'time-row' }, h('span', {}, 'Dalle'), sStart, h('span', {}, 'alle'), sEnd) : null,
    e.school ? h('p', { class: 'caption' }, 'SOS e chiamate funzionano sempre.') : null));
  out.push(h('div', { class: 'section' }, 'Limiti per app'));
  const known = new Map();
  const used = new Map();
  for (const a of S.usage.apps) { known.set(a.pkg, a.label); if (S.usage.day === today()) used.set(a.pkg, a.minutes); }
  // 0.25: apps the child just installed, even before they have minutes.
  for (const a of S.alerts) { const pkg = a.category === L.CAT_NEW_APP && L.newAppPackage(a.text); if (pkg && !known.has(pkg)) known.set(pkg, a.app); }
  for (const l of e.limits) if (!known.has(l.pkg)) known.set(l.pkg, l.label);
  if (!known.size) out.push(h('div', { class: 'card empty' }, h('b', {}, 'Ancora nessuna app'), 'Le app compaiono qui quando arrivano i primi minuti di utilizzo dal telefono di tuo figlio.'));
  for (const [pkg, label] of known) {
    const lim = e.limits.find(l => l.pkg === pkg);
    const sel = h('select', { class: 'limit-select', 'aria-label': 'Limite per ' + label, onchange: ev => {
      const v = Number(ev.target.value);
      e.limits = e.limits.filter(l => l.pkg !== pkg);
      if (v >= 0) e.limits.push({ pkg, label, minutes: v });
    } }, CHOICES.map(c => h('option', { value: String(c), selected: (lim ? lim.minutes : -1) === c }, limitLabel(c))));
    out.push(h('div', { class: 'card app-limit' }, h('div', {}, h('div', { class: 't' }, label),
      h('div', { class: 's' }, used.has(pkg) ? 'Oggi ' + dur(used.get(pkg)) : '')), sel));
  }
  out.push(h('button', { class: 'btn primary', onclick: async ev => {
    ev.target.disabled = true;
    if (await sendRules(e)) { S.editRules = null; toast('Regole inviate: valgono entro un paio di minuti', 4000); go('child'); }
    else { ev.target.disabled = false; toast('Prima collega il telefono di tuo figlio'); }
  } }, 'Salva e manda al telefono di tuo figlio'));
  out.push(h('p', { class: 'caption' }, 'Telefono, contatti, sveglia e Phylax funzionano sempre, anche di notte e a scuola, così tuo figlio può sempre chiamarti.'));
  return out;
}
// ---------- 0.23: site filter ----------
function sitesSummary(r) {
  const on = L.SITE_CATEGORIES.filter(([c]) => (r.sites || []).includes(c)).map(([, l]) => l);
  return on.length ? 'Bloccati: ' + on.join(', ').toLowerCase() : (r.deny || []).length ? (r.deny.length + ' siti bloccati da te') : 'Spento · tocca per attivarlo';
}
function sitesPage() {
  if (!S.editRules) {
    S.editRules = JSON.parse(JSON.stringify(S.rules));
    if (!S.rules.sitesChosen && !(S.rules.sites || []).length) S.editRules.sites = ['ADULT', 'GAMBLING', 'VIOLENCE']; // first time: suggested
  }
  const e = S.editRules;
  e.sites = e.sites || []; e.allow = e.allow || []; e.deny = e.deny || [];
  const out = [header('Filtro siti', 'child'),
    h('p', { class: 'sub' }, 'Nel browser di tuo figlio questi siti mostrano «Sito bloccato». A te arriva un avviso con il nome del sito, una volta al giorno.')];
  out.push(h('div', { class: 'section' }, 'Categorie'));
  const cats = h('div', { class: 'card' });
  for (const [c, label] of L.SITE_CATEGORIES) {
    cats.append(h('label', { class: 'switch-row cat-row' }, h('input', { type: 'checkbox', checked: e.sites.includes(c),
      onchange: ev => { e.sites = ev.target.checked ? [...new Set([...e.sites, c])] : e.sites.filter(x => x !== c); } }), h('span', {}, label)));
  }
  out.push(cats);
  const listCard = (title, key, hint) => {
    const input = h('input', { type: 'text', class: 'site-input', placeholder: 'esempio.it', autocapitalize: 'off', autocomplete: 'off', 'aria-label': title });
    const add = () => {
      const d = L.siteHost(input.value);
      if (!d) { toast('Scrivi solo il nome del sito, per esempio esempio.it'); return; }
      e.allow = e.allow.filter(x => x !== d); e.deny = e.deny.filter(x => x !== d);
      e[key].push(d); render();
    };
    input.addEventListener('keydown', ev => { if (ev.key === 'Enter') add(); });
    return h('div', { class: 'card' }, h('p', { class: 'card-head' }, title), h('p', { class: 'caption' }, hint),
      e[key].map(d => h('div', { class: 'site-row' }, h('span', {}, d),
        h('button', { class: 'link', 'aria-label': 'Togli ' + d, onclick: () => { e[key] = e[key].filter(x => x !== d); render(); } }, 'Togli'))),
      h('div', { class: 'site-add' }, input, h('button', { class: 'btn ghost', onclick: add }, 'Aggiungi')));
  };
  out.push(h('div', { class: 'section' }, 'I tuoi elenchi'));
  out.push(listCard('Sempre bloccati', 'deny', 'Per esempio un sito di giochi che non volete.'));
  out.push(listCard('Sempre consentiti', 'allow', 'Se un sito utile viene bloccato per errore.'));
  out.push(h('button', { class: 'btn primary', onclick: async ev => {
    ev.target.disabled = true;
    e.sitesChosen = true;
    if (await sendRules(e)) { S.editRules = null; toast('Filtro inviato: vale entro un paio di minuti', 4000); go('child'); }
    else { ev.target.disabled = false; toast('Prima collega il telefono di tuo figlio'); }
  } }, 'Salva e manda al telefono di tuo figlio'));
  out.push(h('p', { class: 'caption' }, 'Se sul telefono di tuo figlio è attivo «Filtro siti in tutte le app», il blocco vale anche dentro le app e i giochi, non solo nel browser. Si attiva dalla configurazione di Phylax sul suo telefono.'));
  out.push(h('p', { class: 'caption' }, 'Gli elenchi sono scritti da noi e restano sul telefono di tuo figlio: nessun sito visitato viene mandato, solo quelli bloccati.'));
  return out;
}
async function sendRules(edit) {
  const r = { version: Math.max(S.rules.version + 1, Math.floor(Date.now() / 1000) - 1700000000), night: edit.night, limits: edit.limits,
    school: edit.school !== undefined ? edit.school : (S.rules.school || null),
    sites: edit.sites || [], allow: edit.allow || [], deny: edit.deny || [], sitesChosen: !!edit.sitesChosen,
    places: edit.places || S.rules.places || [] };
  if (!await sendToChild(L.rulesMessage(Date.now(), r))) return false;
  S.rules = r; saveSoon();
  return true;
}
// ---------- 0.24: «Dov'è?» and safe places ----------
async function askWhere() {
  const n = S.where.n + 1;
  if (!await sendToChild(L.locateMessage(Date.now(), n))) return;
  S.where.n = n; S.where.asked = Date.now(); saveSoon();
  toast('Richiesta inviata'); render();
}
function mapUrl(p) {
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  return ios ? 'https://maps.apple.com/?ll=' + p.lat + ',' + p.lon + '&q=Tuo%20figlio'
    : 'https://www.openstreetmap.org/?mlat=' + p.lat + '&mlon=' + p.lon + '#map=17/' + p.lat + '/' + p.lon;
}
function whereCard() {
  const w = S.where, card = h('div', { class: 'card' }), now = Date.now();
  if (w.asked) {
    card.append(h('h3', { class: 'card-title' }, 'Chiesto alle ' + hm(w.asked) + (now - w.asked < 180000 ? ', in attesa…' : ', nessuna risposta ancora')),
      h('p', { class: 'caption' }, 'Di solito arriva in meno di un minuto, se il telefono di tuo figlio è acceso e ha internet.'));
  } else if (w.none && (!w.spot || w.noneTime > w.spot.received)) {
    card.append(h('h3', { class: 'card-title' }, 'Posizione non disponibile'), h('p', { class: 'caption' }, w.none + ' (alle ' + hm(w.noneTime) + ')'));
  }
  if (w.spot) {
    const p = w.spot;
    card.append(h('h3', { class: 'card-title' }, 'Alle ' + hm(p.fixTime) + (p.meters ? ', precisione circa ' + p.meters + ' m' : '')),
      h('p', { class: 'caption' }, p.lat.toFixed(5) + ', ' + p.lon.toFixed(5) + ' · c\'è solo l\'ultima posizione, nessuno storico.'),
      h('a', { class: 'btn outline', href: mapUrl(p), target: '_blank', rel: 'noopener noreferrer' }, 'Apri nella mappa'));
    if (!S.placeForm) card.append(h('button', { class: 'btn outline', onclick: () => { S.placeForm = true; render(); } }, 'Salva come luogo sicuro'));
    else {
      const name = h('input', { type: 'text', class: 'text-input', placeholder: 'Casa, Scuola, Nonni…', maxlength: '30', 'aria-label': 'Nome del luogo' });
      const radius = h('select', { class: 'text-input', 'aria-label': 'Raggio' },
        ...[100, 200, 500].map(r => h('option', r === 200 ? { value: String(r), selected: 'selected' } : { value: String(r) }, 'Entro ' + r + ' m')));
      card.append(h('div', { class: 'place-form' }, name, radius,
        h('p', { class: 'caption' }, 'Ti avvisiamo quando tuo figlio arriva qui o esce, nient\'altro.'),
        h('button', { class: 'btn primary', onclick: async () => {
          const place = L.makePlace(name.value, p.lat, p.lon, Math.max(Number(radius.value), Math.min(1000, p.meters || 0)));
          if (!place) { toast('Scrivi un nome'); return; }
          const list = L.setPlace(S.rules.places || [], place);
          if (list === (S.rules.places || [])) { toast('Al massimo 10 luoghi'); return; }
          if (await sendRules({ ...S.rules, places: list })) { S.placeForm = false; toast('Luogo salvato e mandato'); render(); }
        } }, 'Salva e manda'),
        h('button', { class: 'btn ghost', onclick: () => { S.placeForm = false; render(); } }, 'Annulla')));
    }
  } else if (!w.asked && !w.none) {
    card.append(h('p', {}, 'Chiedi dove si trova il telefono di tuo figlio: risponde una volta sola, e lui vede una notifica.'));
  }
  card.append(h('button', { class: 'btn primary', onclick: askWhere }, w.spot ? 'Chiedi di nuovo' : 'Chiedi dov\'è'));
  card.append(h('h3', { class: 'card-title sub' }, 'Luoghi sicuri'));
  const places = S.rules.places || [];
  if (!places.length) card.append(h('p', { class: 'caption' }, 'Nessuno. Dopo una posizione puoi salvarla come «Casa» o «Scuola»: ti avvisiamo solo quando arriva o esce.'));
  for (const pl of places) {
    const e = w.places[pl.name];
    card.append(h('div', { class: 'site-row' }, h('span', {}, pl.name + ' (' + pl.radius + ' m)' + (e ? ' · ' + (e.arrived ? 'arrivato alle ' : 'uscito alle ') + hm(e.time) : '')),
      h('button', { class: 'link', 'aria-label': 'Togli ' + pl.name, onclick: async () => {
        if (!confirm('Togliere «' + pl.name + '»?')) return;
        if (await sendRules({ ...S.rules, places: places.filter(x => x.name !== pl.name) })) render();
      } }, 'Togli')));
  }
  if (places.length) card.append(h('p', { class: 'caption' }, 'Sul telefono di tuo figlio serve la posizione «sempre».'));
  return card;
}
async function answerExtra(r, yes) {
  if (!await sendToChild(L.extraMessage(Date.now(), r.pkg, r.label, r.minutes, yes ? L.EXTRA_YES : L.EXTRA_NO))) return;
  S.requests = S.requests.filter(x => x.pkg !== r.pkg); saveSoon();
  toast(yes ? r.minutes + ' minuti in più per ' + r.label : 'Risposta inviata'); render();
}

function settingsPage() {
  const out = [header('Impostazioni')];
  out.push(h('div', { class: 'section' }, 'Avvisi'));
  out.push(navRow('🔔', 'Notifiche', pushLine(), () => go('notify'), true));
  out.push(h('div', { class: 'section' }, 'Sicurezza'));
  out.push(navRow('#', 'Cambia PIN', 'Il PIN che apre questa app', () => go('pin')));
  if (S.bio || S.bioAvailable) {
    out.push(navRow('☺', 'Sblocca con Face ID', S.bio ? 'Attivo · tocca per spegnerlo' : 'Spento · tocca per attivarlo', toggleBio));
  }
  out.push(navRow('🔒', 'Blocca ora', S.bio ? 'Chiede Face ID o il PIN' : 'Chiede di nuovo il PIN', () => { S.unlocked = false; render(); }));
  out.push(h('div', { class: 'section' }, 'Figli'));
  out.push(navRow('✎', 'Nome del figlio', childName(S.slot) + ' · tocca per cambiarlo', renameChild));
  out.push(navRow('📱', 'Telefono di tuo figlio', 'Collegamento e codice di verifica', () => go('pair')));
  if (S.family.slots.length < MAX_CHILDREN) out.push(navRow('+', 'Aggiungi un figlio', 'Fino a ' + MAX_CHILDREN + ' figli, ognuno con il suo telefono', addChild));
  out.push(navRow('💬', 'Come parlarne con tuo figlio', 'Prima di installarlo, per età, quando arriva un avviso', () => go('talk')));
  if (S.pair) out.push(navRow('−', 'Togli questo figlio', 'Toglie ' + childName(S.slot) + ' da questa app', removeChild));
  out.push(h('div', { class: 'section' }, 'Altro'));
  out.push(navRow('ⓘ', 'Avanzate e informazioni', 'Versione, collegamento, privacy', () => go('advanced')));
  return out;
}

/** 0.21: everything technical lives here, out of the main screens. */
function advancedPage() {
  const out = [header('Avanzate', 'settings')];
  const conn = !S.pair ? 'Non abbinato' : S.online ? 'In ascolto (casella cifrata)' : S.loaded ? 'Non collegato: nuovo tentativo…' : 'Collegamento alla casella…';
  out.push(h('div', { class: 'card' },
    h('p', { class: 'card-head' }, 'Collegamento'),
    h('p', {}, h('span', { class: 'dot' + (S.online ? ' on' : '') }), conn, S.error ? ' · ' + S.error : ''),
    h('p', { class: 'caption' }, 'Gli avvisi passano dalla nostra casella cifrata (Cloudflare), che tiene solo testo cifrato per 7 giorni. Qui restano salvati cifrati, con la chiave protetta dal PIN o da Face ID.')));
  out.push(h('div', { class: 'card' },
    h('p', { class: 'card-head' }, 'Informazioni'),
    h('p', {}, 'Versione web ' + VERSION),
    h('p', { class: 'caption' }, 'PIN: PBKDF2-SHA256 sul telefono. Avvisi: cifratura punto a punto (ECDH P-256, AES-GCM). Notifiche: testo fisso, senza contenuto.'),
    h('p', { class: 'caption' }, 'Carattere del logo: Baloo 2 (SIL Open Font License). Solo prove con messaggi inventati [TUTELA-TEST].')));
  return out;
}

function alertCard(a, archived) {
  const level = a.high ? ['danger', 'Urgente'] : a.doubt ? ['doubt', 'Dubbio'] : ['warning', 'Da guardare'];
  const note = a.category === 'Possibile foto intima'
    ? '📷 L\'immagine resta sul telefono di tuo figlio e non viene mai inviata. Non chiedere di vederla o di inoltrartela.'
    : /visualizzazione singola/i.test(a.category)
      ? '👁 Phylax vede solo che c\'è stato un contenuto che si apre una volta, non cosa contiene. Parlane con calma: a volte è uno scherzo, a volte una pressione.'
      : /vocali/i.test(a.category) ? '🎙 Phylax non ascolta i vocali: conta solo quanti ne arrivano di notte.'
      : a.category === L.CAT_SOS ? '🆘 Se ha la posizione attiva, la trovi in Figlio › Dov\'è?. Chiamalo.' : null;
  const limit = a.category === L.CAT_NEW_APP && L.newAppPackage(a.text)
    ? h('button', { class: 'link', onclick: () => { S.editRules = null; go('time'); } }, 'Dai un limite o mettila in pausa ›') : null;
  return h('div', { class: 'card alert ' + level[0] + (archived ? ' archived' : '') },
    h('div', { class: 'alert-top' }, h('span', { class: 'chip ' + level[0] }, level[1]), h('span', { class: 'time' }, hm(a.time))),
    h('h3', {}, a.category), h('p', { class: 'meta' }, a.app), h('div', { class: 'quote' }, a.text),
    note ? h('p', { class: 'caption' }, note) : null, limit,
    archived ? null : h('button', { class: 'link', onclick: () => go('talk/' + encodeURIComponent(a.category)) }, 'Come parlarne ›'),
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
  const out = [header('Chat da controllare', true), h('p', { class: 'sub' }, 'Vedi solo questa chat, e solo dall\'avviso in poi.')];
  if (!r) { out.push(h('div', { class: 'card empty' }, h('b', {}, 'Segnalazione chiusa o non più disponibile.'))); return out; }
  out.push(h('div', { class: 'card' },
    h('h3', { class: 'card-title' }, r.reason),
    h('p', { class: 'meta' }, r.app + ' · aperta alle ' + hm(r.opened)),
    r.fragments.map(f => h('div', { class: 'bubble' }, f.text, h('span', { class: 'bt' }, hm(f.time))))));
  const language = r.reason === 'Lingua o codice non riconosciuto'; // 0.13: same command as "Tutto ok"
  out.push(h('button', { class: 'btn outline', onclick: e => { e.target.disabled = true; closeReport(id, L.OUTCOME_OK); } }, language ? 'Questa lingua va bene · chiudi e cancella' : 'Tutto ok · chiudi e cancella'));
  if (language) out.push(h('p', { class: 'caption' }, 'Per questa chat Phylax non avviserà più solo per la lingua; le parole a rischio continuano a far partire gli avvisi.'));
  out.push(h('button', { class: 'btn primary', onclick: e => { e.target.disabled = true; closeReport(id, L.OUTCOME_INTERVENE); } }, 'Intervengo · chiudi e cancella'));
  out.push(h('p', { class: 'caption' }, 'Chiudendo, questi messaggi si cancellano qui e, entro un paio di minuti, anche sul telefono di tuo figlio.'));
  return out;
}

function pairPage() {
  const out = [header('Collegamento', S.pair ? 'child' : true)];
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
    h('p', { class: 'meta' }, S.child ? 'Codice di collegamento' : 'Se non riesci a usare il QR, copia questo codice'),
    box,
    h('div', { class: 'gap' }),
    h('button', { class: 'btn primary', onclick: () => copy(S.pair.code, 'Codice') }, 'Copia'),
    h('button', { class: 'btn ghost', onclick: () => { S.showCode = !S.showCode; render(); } }, S.showCode ? 'Nascondi codice' : 'Mostra codice'),
    S.child ? null : h('ol', { class: 'steps' },
      h('li', {}, 'Sul telefono di tuo figlio: Phylax › Telefono del genitore › PIN genitore.'),
      h('li', {}, 'Fotografa il QR qui sopra (o incolla il codice) e tocca Abbina.'),
      h('li', {}, 'Qui comparirà il codice di verifica a 6 cifre.'))));
  out.push(h('p', { class: 'caption' }, 'Mamma e papà: anche l\'altro genitore abbina la sua app allo stesso telefono. Sul telefono del figlio: Phylax › PIN › Telefono del genitore › «Aggiungi l\'altro genitore». Ricevete gli stessi avvisi e vedete le stesse regole.'));
  out.push(h('button', { class: 'btn danger', onclick: async () => {
    if (!confirm('Nuovo abbinamento? Il telefono di tuo figlio non potrà più raggiungere questa app finché non incolli il nuovo codice.')) return;
    await newPairing(); render();
  } }, 'Nuovo abbinamento'));
  return out;
}

// ---------- 0.28: «La settimana» ----------
const MONTHS = ['gennaio', 'febbraio', 'marzo', 'aprile', 'maggio', 'giugno', 'luglio', 'agosto', 'settembre', 'ottobre', 'novembre', 'dicembre'];
function weekRange(monday) {
  const d = new Date(monday + 'T12:00:00'); if (isNaN(d)) return '';
  const e = new Date(d); e.setDate(d.getDate() + 6);
  return 'Dal ' + d.getDate() + ' ' + MONTHS[d.getMonth()] + ' al ' + e.getDate() + ' ' + MONTHS[e.getMonth()];
}
const change = (now, before) => before <= 0 ? (now > 0 ? 'nuova' : '') : (p => Math.abs(p) < 5 ? 'uguale' : (p > 0 ? '+' : '−') + Math.abs(p) + '%')(Math.round(100 * (now - before) / before));
/** Same choice as WeekActivity.tip: advice for the most frequent alert, else about the time trend, else a calm-week tip. */
function weekTip(w) {
  if (!advice) return null;
  const low = (w.topKind || '').toLowerCase();
  const t = w.topKind ? advice.topics.find(x => x.match.some(m => low.includes(m))) : null;
  if (t) return [t.title, t.points[0]];
  if (!advice.week) return null;
  if (w.trend !== null && w.trend >= 10) return ['', advice.week.more];
  if (w.trend !== null && w.trend <= -10) return ['', advice.week.less];
  const idx = Math.floor((Math.round(new Date(w.weekStart + 'T00:00:00Z').getTime() / 86400000) - 4) / 7);
  return ['', advice.week.calm[((idx % advice.week.calm.length) + advice.week.calm.length) % advice.week.calm.length]];
}
function bars(rows, max) {
  return rows.map(([label, minutes, note]) => {
    const fill = h('div', { class: 'bar-fill' });
    fill.style.width = Math.max(minutes > 0 ? 3 : 0, Math.round(100 * Math.min(1, minutes / Math.max(1, max)))) + '%';
    return [h('div', { class: 'usage-row' }, h('span', { class: 'u-name' }, label), h('span', { class: 'u-min' }, (minutes >= 0 ? dur(minutes) : '') + (note ? (minutes >= 0 ? ' · ' : '') + note : ''))),
      h('div', { class: 'bar' }, fill)];
  }).flat();
}
function weekPage() {
  loadAdvice();
  const w = S.week ? L.parseWeek(S.week.weekStart, S.week.lines) : null;
  const out = [header('La settimana', 'child')];
  if (!w) { out.push(h('div', { class: 'card empty' }, h('b', {}, 'Ancora nessun resoconto'), 'Arriva la domenica sera dal telefono di tuo figlio, cifrato come gli avvisi.')); return out; }
  out.push(h('p', { class: 'sub' }, weekRange(w.weekStart)));
  out.push(h('div', { class: 'section' }, 'Tempo davanti allo schermo'));
  const DAYS = ['Lun', 'Mar', 'Mer', 'Gio', 'Ven', 'Sab', 'Dom'];
  if (w.average < 0) out.push(h('div', { class: 'card' }, h('p', {}, 'Nessun dato: sul telefono di tuo figlio manca «Consenti accesso ai dati di utilizzo».')));
  else {
    const tw = L.trendWord(w.trend);
    out.push(h('div', { class: 'card' }, h('h3', { class: 'card-title' }, 'In media ' + dur(w.average) + ' al giorno'),
      h('p', { class: 'caption' }, 'In tutto ' + dur(w.total) + (tw ? ' · ' + tw : '') + '.'),
      ...bars(w.days.map((d, i) => [DAYS[i], d < 0 ? 0 : d, d < 0 ? 'nessun dato' : '']), Math.max(...w.days))));
  }
  if (w.apps.length) {
    out.push(h('div', { class: 'section' }, 'App più usate'));
    out.push(h('div', { class: 'card' }, ...bars(w.apps.map(a => [a.label, a.minutes, change(a.minutes, a.before)]), w.apps[0].minutes)));
  }
  out.push(h('div', { class: 'section' }, 'Avvisi'));
  out.push(w.alerts === 0
    ? h('div', { class: 'card' }, h('p', {}, w.alertsBefore === 0 ? 'Nessun avviso, come la settimana prima.' : 'Nessun avviso (la settimana prima: ' + w.alertsBefore + ').'))
    : h('div', { class: 'card' }, h('h3', { class: 'card-title' }, w.alerts + (w.alerts === 1 ? ' avviso' : ' avvisi') + ' (la settimana prima: ' + w.alertsBefore + ')'),
      h('ul', { class: 'plain' }, ...w.kinds.filter(k => k.count || k.before).map(k => h('li', {}, k.category + ': ' + k.count + (k.before !== k.count ? '  (prima ' + k.before + ')' : ''))))));
  const tip = weekTip(w);
  if (tip) {
    out.push(h('div', { class: 'section' }, 'Il consiglio della settimana'));
    out.push(h('div', { class: 'card' }, tip[0] ? h('h3', { class: 'card-title' }, tip[0]) : null, h('p', {}, tip[1]),
      h('button', { class: 'btn', onclick: () => go('talk' + (w.topKind ? '/' + encodeURIComponent(w.topKind) : '')) }, 'Come parlarne ›')));
  }
  out.push(h('p', { class: 'caption' }, 'Solo numeri: Phylax non manda le chat, i siti visitati o dove è stato. Arrivato il ' + hm(S.week.time) + '.'));
  return out;
}

// ---------- 0.26: «Come parlarne» (advice.json, the same file the Android parent app uses) ----------
let advice = null, adviceAsked = false;
function loadAdvice() {
  if (adviceAsked) return;
  adviceAsked = true;
  fetch('advice.json').then(r => r.json()).then(j => { advice = j; scheduleRender(); }).catch(() => { adviceAsked = false; });
}
function talkPage(topic) {
  const out = [header('Come parlarne', true), h('p', { class: 'sub' }, 'Consigli per genitori, non regole: ogni ragazzo è diverso.')];
  loadAdvice();
  if (!advice) { out.push(h('p', { class: 'caption' }, 'Carico i consigli…')); return out; }
  const block = s => [h('div', { class: 'section' }, s.title), h('div', { class: 'card' }, h('ul', { class: 'plain' }, ...s.points.map(p => h('li', {}, p))))];
  const low = (topic || '').toLowerCase();
  const t = topic ? advice.topics.find(x => x.match.some(m => low.includes(m))) : null;
  if (t) out.push(...block(t));
  out.push(h('p', {}, advice.intro));
  for (const s of advice.sections) out.push(...block(s));
  if (!t) { out.push(h('div', { class: 'section' }, 'Per argomento')); for (const x of advice.topics) out.push(h('div', { class: 'card' }, h('h3', { class: 'card-title' }, x.title), h('ul', { class: 'plain' }, ...x.points.map(p => h('li', {}, p))))); }
  out.push(h('div', { class: 'section' }, 'A chi chiedere aiuto'));
  out.push(h('div', { class: 'card' }, ...advice.help.map(x => h('p', {}, x))));
  out.push(h('p', { class: 'caption' }, 'Testi di Phylax: non sostituiscono un professionista.'));
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
  const out = [header('Notifiche', 'settings'),
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
    : S.subscribed && S.child ? 'Permesso dato. In attesa della conferma del telefono di tuo figlio (entro un paio di minuti).'
    : 'Notifiche spente.';
  out.push(h('div', { class: 'card' },
    h('p', { class: 'card-head' }, state),
    S.pushError ? h('p', { class: 'err' }, S.pushError) : null,
    (!S.subscribed || S.pushState === 'expired' || !S.pushState)
      ? h('button', { class: 'btn primary', onclick: enablePush }, S.pushState === 'expired' ? 'Riattiva notifiche' : 'Attiva notifiche')
      : h('button', { class: 'btn ghost', onclick: () => { resendPush(true); toast('Richiesta inviata'); render(); } }, 'Invia di nuovo al telefono di tuo figlio')));
  out.push(h('div', { class: 'card' },
    h('p', { class: 'card-head' }, 'Privacy'),
    h('p', { class: 'caption' }, 'Non serve un account. Apple riceve solo una notifica cifrata con un testo fisso, senza nomi, chat o categorie.')));
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
    S.family = await db.get('family') || { slots: await db.get('pair') ? [0] : [], names: {}, current: 0 };
    S.slot = S.family.current || 0;
    await loadChild();
  } catch {
    document.getElementById('app').replaceChildren(h('p', { class: 'caption center' }, 'Memoria del browser non disponibile (navigazione privata?).'));
    return;
  }
  render();
  Bio.available().then(v => { S.bioAvailable = v; scheduleRender(); });
  if (S.outbox.length) drain();
  if (pushSupported() && standalone()) { vapid().catch(() => {}); resendPush(false).then(scheduleRender); }
})();
