// Tutela Genitore — web app (PWA) for the parent's iPhone. Same protocol and look as the Android app.
// Stores on this device ONLY: the key pair (private key not extractable), topics, counters, PIN hash,
// last contact time. Alerts and reports are NOT stored: at every opening they are rebuilt by decrypting what
// ntfy.sh still keeps (about 12 hours, ciphertext only), including our own "close" messages.
import * as L from './link.js';

const VERSION = '0.10.3';
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
  sent: 0, seenMax: 0, lastSeenSaved: 0,
  alerts: [], reports: new Map(), state: null, detail: '', lastSeen: 0, lastStatus: 0,
  lastId: 'all', lastC2P: 0, lastP2C: 0,
  online: false, loaded: false, error: '', outbox: [], outboxWait: 5000,
  showCode: true, archived: new Map(), showArchived: false,
  pushState: null, subscribed: false, pushSentEndpoint: null, pushError: '',
};
let streamCtrl = null, reconnectTimer = null, lastActivity = 0, queue = Promise.resolve();

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
function toast(text) {
  const t = document.getElementById('toast');
  t.textContent = text; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 2500);
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
async function pinHash(pin, salt, iterations) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 256));
}
async function setPin(pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  S.pin = { salt: L.b64(salt), hash: L.b64(await pinHash(pin, salt, PBKDF2_ITERATIONS)), iterations: PBKDF2_ITERATIONS };
  await db.set('pin', S.pin);
}
async function checkPin(pin) {
  const got = await pinHash(pin, L.unb64(S.pin.salt), S.pin.iterations), want = L.unb64(S.pin.hash);
  let diff = got.length ^ want.length;
  for (let i = 0; i < got.length; i++) diff |= got[i] ^ want[i];
  return diff === 0;
}

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
}
function closeLocally(id) {
  const r = S.reports.get(id);
  if (r) for (const a of S.alerts) if (!a.archived && S.archived.get(alertKey(a)) !== false && linked(a, r)) setArchived(a, true);
  S.reports.delete(id);
}

function resetData() {
  S.alerts = []; S.reports = new Map(); S.state = null; S.detail = ''; S.lastStatus = 0;
  S.lastId = 'all'; S.lastC2P = 0; S.lastP2C = 0;
}
function apply(m, receivedAt) {
  S.lastSeen = Math.max(S.lastSeen, receivedAt);
  switch (m.type) {
    case 'ALERT':
      S.alerts.unshift({ high: m.level === L.LEVEL_HIGH, category: m.category, app: m.app, text: m.text, time: m.time });
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

/** One ntfy message. Foreign, altered, replayed, too old: ignored. `live` = arrived now (not the backlog). */
async function handle(ev, live) {
  if (ev.id) S.lastId = ev.id;
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
      const fresh = header.counter > S.seenMax;
      if (fresh) { S.seenMax = header.counter; db.set('seenMax', S.seenMax); }
      if (S.lastSeen - S.lastSeenSaved > 60000) { S.lastSeenSaved = S.lastSeen; db.set('lastSeen', S.lastSeen); }
      if (live && fresh) announce(what, m);
    } else if (hd.direction === L.P2C && await ensureKeys()) {
      // Our own "close report" (also from another device with this pairing): the report is gone.
      const { header, plaintext } = await L.open(S.keys.p2c, L.P2C, ev.message, S.lastP2C);
      S.lastP2C = header.counter;
      const m = L.decodeMessage(plaintext);
      if (m.type === 'CLOSE_CASE') closeLocally(m.caseId);
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
    navigator.serviceWorker?.ready.then(reg => reg.showNotification('Tutela Genitore', { body: text, tag: 'tutela', icon: 'icons/icon-192.png' })).catch(() => {});
  }
}

// ---------- ntfy connection ----------
function enqueue(fn) { queue = queue.then(fn, fn); return queue; }
async function connect() {
  if (!S.pair || streamCtrl) return;
  clearTimeout(reconnectTimer);
  const ctrl = streamCtrl = new AbortController();
  try {
    if (!S.loaded) {
      // Backlog first (rebuilds the state), then the live stream from the last id.
      const backlog = await L.poll(S.pair.topic, 'all');
      for (const ev of backlog) await enqueue(() => handle(ev, false));
      S.loaded = true;
    }
    S.online = true; S.error = ''; scheduleRender();
    await L.stream(S.pair.topic, S.lastId, ev => enqueue(() => handle(ev, true)), ctrl.signal, () => { lastActivity = Date.now(); });
  } catch (e) {
    if (!ctrl.signal.aborted) S.error = 'Connessione a ntfy non riuscita: nuovo tentativo tra poco.';
  }
  if (streamCtrl === ctrl) {
    streamCtrl = null; S.online = false; scheduleRender();
    if (!ctrl.signal.aborted || ctrl.reconnect) reconnectTimer = setTimeout(connect, ctrl.reconnect ? 0 : 5000);
  }
}
function disconnect(reconnect) {
  if (!streamCtrl) { if (reconnect) connect(); return; }
  streamCtrl.reconnect = reconnect;
  streamCtrl.abort();
}
// ntfy keepalive ~45 s: nothing for 100 s (e.g. iPhone back from the background) means a dead stream.
setInterval(() => { if (streamCtrl && S.online && Date.now() - lastActivity > 100000) disconnect(true); scheduleRender(); }, 30000);

async function closeReport(id, outcome) {
  if (!await ensureKeys()) return;
  S.sent = L.nextCounter(S.sent, Date.now());
  await db.set('sent', S.sent);
  const wire = await L.seal(S.keys.p2c, L.P2C, null, S.sent, L.closeMessage(Date.now(), id, outcome));
  closeLocally(id);
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
    try { await L.publish(S.pair.topic, S.outbox[0]); S.outbox.shift(); S.outboxWait = 5000; await db.set('outbox', S.outbox); }
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
    if (perm !== 'granted') { S.pushError = 'Notifiche non consentite. Per attivarle: Impostazioni › Notifiche › Tutela Genitore.'; render(); return; }
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
  // v1 code: no separate ntfy notification topic any more, notifications come by Web Push (0.10.3).
  S.pair = { topic, notifyTopic: null, priv: kp.privateKey, pub, code: L.pairingCode(topic, pub), created: Date.now() };
  S.child = null; S.keys = null; S.pushState = null; S.pushSentEndpoint = null; S.sent = 0; S.seenMax = 0; S.lastSeen = 0; S.outbox = []; S.loaded = false; S.showCode = true;
  resetData();
  await db.set('pair', S.pair);
  S.archived = new Map();
  for (const k of ['child', 'sent', 'seenMax', 'lastSeen', 'outbox', 'archived', 'pushSent', 'pushState']) await db.del(k);
  disconnect(true);
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
  if (!S.unlocked) return pinPage('Tutela Genitore', 'Inserisci il PIN.', false);
  const [name, arg] = r.split('/');
  if (name === 'report') return reportPage(Number(arg));
  if (name === 'pair') return pairPage();
  if (name === 'notify') return notifyPage();
  if (name === 'pin') return pinPage('Cambia PIN', 'Nuovo PIN, almeno 6 cifre.', true, true);
  return homePage();
}

function pinPage(title, sub, choosing, change) {
  const input = h('input', { class: 'pin-input', type: 'password', inputmode: 'numeric', autocomplete: 'off', maxlength: '12', 'aria-label': 'PIN' });
  const again = choosing ? h('input', { class: 'pin-input', type: 'password', inputmode: 'numeric', autocomplete: 'off', maxlength: '12', placeholder: 'ripeti', 'aria-label': 'Ripeti il PIN' }) : null;
  const err = h('p', { class: 'err' });
  const submit = async () => {
    const pin = input.value.trim();
    if (choosing) {
      if (!/^\d{6,12}$/.test(pin)) { err.textContent = 'Usa da 6 a 12 cifre.'; return; }
      if (pin !== again.value.trim()) { err.textContent = 'I due PIN non coincidono.'; return; }
      btn.disabled = true;
      await setPin(pin); S.unlocked = true; toast(change ? 'PIN cambiato' : 'PIN impostato');
      if (change) go(''); else render();
      return;
    }
    if (Date.now() < S.pinWaitUntil) { err.textContent = 'Troppi tentativi: riprova tra ' + Math.ceil((S.pinWaitUntil - Date.now()) / 1000) + ' s.'; return; }
    btn.disabled = true;
    if (await checkPin(pin)) { S.unlocked = true; S.pinFails = 0; render(); connect(); return; }
    S.pinFails++;
    if (S.pinFails >= 5) { S.pinWaitUntil = Date.now() + 30000 * Math.pow(2, S.pinFails - 5); }
    btn.disabled = false; input.value = ''; err.textContent = 'PIN errato.';
  };
  const btn = h('button', { class: 'btn primary', onclick: submit }, choosing ? 'Salva PIN' : 'Sblocca');
  const onKey = e => { if (e.key === 'Enter') submit(); };
  input.addEventListener('keydown', onKey); again && again.addEventListener('keydown', onKey);
  setTimeout(() => input.focus(), 50);
  return [h('div', { class: 'lock' },
    change ? header(title, true) : h('div', { class: 'head' }, shield(), h('h1', {}, title)),
    h('p', { class: 'sub' }, sub), input, again, err, btn,
    change ? null : h('p', { class: 'caption center' }, 'Il PIN resta solo su questo telefono (PBKDF2). Se lo dimentichi: abbina di nuovo.'))];
}

function statusCard() {
  const now = Date.now();
  let cls = '', title, line, action = 'Abbinamento e codice di verifica';
  if (!S.pair) { title = 'Non abbinato'; line = 'Abbina il telefono di tuo figlio con un codice.'; action = 'Abbina'; }
  else if (!S.child) { title = 'In attesa del telefono di tuo figlio'; line = 'Incolla il codice in Tutela sul suo telefono › Telefono del genitore.'; }
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
  const out = [header('Tutela Genitore'), h('p', { class: 'sub' }, 'Avvisi cifrati dal telefono di tuo figlio.'), statusCard()];
  if (S.pair) {
    out.push(h('p', { class: 'caption' }, h('span', { class: 'dot' + (S.online ? ' on' : '') }),
      S.online ? 'In ascolto (ntfy.sh, solo testo cifrato)' : 'Non collegato: riconnessione…', S.error ? ' · ' + S.error : ''));
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
  if (!active.length) out.push(h('div', { class: 'card empty' }, h('b', {}, 'Nessun avviso.'), 'Gli avvisi arrivano cifrati; questa app non li salva sul telefono.'));
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
  out.push(navRow('🔒', 'Blocca ora', 'Chiede di nuovo il PIN', () => { S.unlocked = false; render(); }));
  out.push(h('p', { class: 'caption center' }, 'Versione web ' + VERSION + ' · consegna tramite ntfy.sh (gratuito, solo testo cifrato) · '
    + 'gli avvisi restano cifrati sul server per circa 12 ore e non vengono salvati qui · solo prove con messaggi inventati [TUTELA-TEST]'));
  return out;
}
function alertCard(a, archived) {
  return h('div', { class: 'card alert' + (archived ? ' archived' : '') },
    h('div', { class: 'alert-top' }, h('span', { class: 'chip ' + (a.high ? 'danger' : 'warning') }, a.high ? 'Rischio alto' : 'Da verificare'),
      h('span', { class: 'time' }, hm(a.time))),
    h('h3', {}, a.category), h('p', { class: 'meta' }, a.app), h('div', { class: 'quote' }, a.text),
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
  out.push(h('button', { class: 'btn outline', onclick: e => { e.target.disabled = true; closeReport(id, L.OUTCOME_OK); } }, 'Tutto ok · chiudi e cancella'));
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
        h('li', {}, 'Tocca «Crea codice di abbinamento» e poi «Copia».'),
        h('li', {}, 'Mandalo sul telefono di tuo figlio (o scrivilo): Tutela › Telefono del genitore › PIN genitore › incolla › Abbina.'),
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
  out.push(h('div', { class: 'card' },
    h('p', { class: 'meta' }, 'Codice di abbinamento (contiene solo la chiave pubblica e i due topic)'),
    box,
    h('div', { class: 'gap' }),
    h('button', { class: 'btn primary', onclick: () => copy(S.pair.code, 'Codice') }, 'Copia'),
    h('button', { class: 'btn ghost', onclick: () => { S.showCode = !S.showCode; render(); } }, S.showCode ? 'Nascondi codice' : 'Mostra codice'),
    S.child ? null : h('ol', { class: 'steps' },
      h('li', {}, 'Sul telefono di tuo figlio: Tutela › Telefono del genitore › PIN genitore.'),
      h('li', {}, 'Incolla il codice e tocca Abbina.'),
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
  if (S.subscribed && S.pushState === 'ok') return 'Attive · solo «Nuovo avviso da Tutela: apri l\'app»';
  if (S.subscribed && S.child) return 'In attesa del telefono di tuo figlio…';
  return 'Spente: tocca qui per attivarle';
}
function notifyPage() {
  const out = [header('Notifiche', true),
    h('p', { class: 'sub' }, 'Il telefono di tuo figlio fa suonare questo iPhone. La notifica dice solo «Nuovo avviso da Tutela: apri l\'app»: il contenuto lo vedi solo qui, con il PIN.')];
  if (!pushSupported() || !standalone()) {
    out.push(h('div', { class: 'card' },
      h('p', { class: 'card-head' }, 'Prima aggiungi l\'app alla schermata Home'),
      h('ol', { class: 'steps' },
        h('li', {}, 'Apri questa pagina in Safari.'),
        h('li', {}, 'Tocca Condividi (il quadrato con la freccia) › «Aggiungi alla schermata Home».'),
        h('li', {}, 'Apri Tutela Genitore dall\'icona sulla Home e torna qui: comparirà «Attiva notifiche».')),
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
    h('p', { class: 'caption' }, 'Nessun server nostro e nessun account. Il servizio notifiche di Apple riceve solo una notifica cifrata con un testo fisso, senza nomi, chat o categorie. L\'indirizzo delle notifiche passa al telefono di tuo figlio solo cifrato.')));
  return out;
}

// ---------- Start ----------
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') { S.hiddenAt = Date.now(); return; }
  if (S.hiddenAt && Date.now() - S.hiddenAt > LOCK_AFTER_MS) { S.unlocked = false; }
  try { navigator.clearAppBadge && navigator.clearAppBadge(); } catch { /* not supported */ }
  if (S.pair && !streamCtrl) connect();
  scheduleRender();
});
window.addEventListener('hashchange', () => { render(); window.scrollTo(0, 0); });
window.addEventListener('online', () => { drain(); if (!streamCtrl) connect(); });

(async function start() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
  try {
    S.pin = await db.get('pin') || null;
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
  if (S.outbox.length) drain();
  if (pushSupported() && standalone()) { vapid().catch(() => {}); resendPush(false).then(scheduleRender); }
})();
