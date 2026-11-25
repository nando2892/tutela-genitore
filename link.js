// Phylax Genitore (web) — protocol 0.10 of the child app, in WebCrypto. Mirrors SecureLink.java and
// LinkMessage.java byte for byte (cross-checked against the Java code). No libraries, no CDN.
// ECDH P-256 -> HKDF-SHA256 -> AES-256-GCM per direction, 12-byte random nonce, counter against replays.

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = globalThis.crypto.subtle;

export const CODE_PREFIX = 'TG1.', WIRE_PREFIX = 'T1.';
export const C2P = 1, P2C = 2, WIRE_VERSION = 1, TOPIC_LENGTH = 32;
// 0.22: USAGE (child: minutes per app), RULES (parent: screen-time rules), EXTRA (more time: asked / granted / refused).
export const TYPES = ['ALERT', 'CASE_OPEN', 'CASE_FRAGMENTS', 'STATUS', 'CLOSE_CASE', 'PUSH', 'USAGE', 'RULES', 'EXTRA', 'LOCATION', 'WEEK', 'APPS']; // 0.28: WEEK = weekly summary; 0.29: APPS = installed apps
export const EXTRA_ASK = 0, EXTRA_YES = 1, EXTRA_NO = 2;
/** 0.24 LOCATION: parent asks (LOC_ASK), child answers once (LOC_HERE «lat,lon,metri,ora» / LOC_NONE why) or a safe place event. */
export const LOC_ASK = 0, LOC_HERE = 1, LOC_NONE = 2, LOC_PLACE = 3;
/** 0.25: STATUS outcome = battery info (level = %), BATTERY_LOW = «quasi scarica»; alert categories that are information. */
export const BATTERY_INFO = 1, BATTERY_LOW = 2, CAT_SOS = 'SOS', CAT_NEW_APP = 'Nuova app installata', CAT_ACCESS = 'Accesso tolto';
/** Package in brackets at the end of a «Nuova app installata» text, or null (same as LinkMessage.newAppPackage). */
export function newAppPackage(text) {
  const t = String(text || ''), a = t.lastIndexOf('('), b = t.lastIndexOf(')');
  if (a < 0 || b <= a + 1) return null;
  const p = t.slice(a + 1, b);
  return /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(p) ? p : null;
}
export const PUSH_ACTIVE = 1, PUSH_EXPIRED = 2;
export const STATES = ['ACTIVE', 'INTERRUPTED', 'RESUMED', 'STOPPED', 'PAIRED'];
export const LEVEL_HIGH = 1, LEVEL_DOUBT = 2, OUTCOME_OK = 1, OUTCOME_INTERVENE = 2;
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';

export function b64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64(text) {
  const s = text.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** 32 base32 chars = 160 random bits, like SecureLink.newTopic(). */
export function newTopic() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(20));
  let out = '', buffer = 0, bits = 0;
  for (const b of bytes) {
    buffer = ((buffer << 8) | b) & 0xffff; bits += 8;
    while (bits >= 5) { out += B32[(buffer >> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}
export function validTopic(t) { return typeof t === 'string' && t.length === TOPIC_LENGTH && [...t].every(c => B32.includes(c)); }

/** Private key NOT extractable: it can only be used for ECDH inside the browser. */
export function newKeyPair() {
  return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
}
export async function spki(publicKey) { return new Uint8Array(await subtle.exportKey('spki', publicKey)); }
export function importPublic(spkiBytes) {
  return subtle.importKey('spki', spkiBytes, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

/** Code v1: version 1 | topic | parent's public key. Used by the web app since 0.10.3 (notifications via Web Push). */
export function pairingCode(topic, parentSpki) {
  return CODE_PREFIX + b64(concat(new Uint8Array([1]), enc.encode(topic), parentSpki));
}
/** Code v2: version 2 | topic | notification topic | parent's public key (SPKI = Java X.509). */
export function pairingCodeV2(topic, notifyTopic, parentSpki) {
  return CODE_PREFIX + b64(concat(new Uint8Array([2]), enc.encode(topic), enc.encode(notifyTopic), parentSpki));
}
export function parsePairing(code) {
  const c = (code || '').replace(/\s/g, '');
  if (!c.startsWith(CODE_PREFIX)) throw new Error('Codice non valido');
  const raw = unb64(c.slice(CODE_PREFIX.length));
  const v = raw[0];
  if (v !== 1 && v !== 2) throw new Error('Versione non supportata');
  const keyAt = v === 2 ? 1 + 2 * TOPIC_LENGTH : 1 + TOPIC_LENGTH;
  if (raw.length < keyAt + 60) throw new Error('Codice incompleto');
  const topic = dec.decode(raw.slice(1, 1 + TOPIC_LENGTH));
  const notifyTopic = v === 2 ? dec.decode(raw.slice(1 + TOPIC_LENGTH, 1 + 2 * TOPIC_LENGTH)) : null;
  if (!validTopic(topic) || (notifyTopic !== null && (!validTopic(notifyTopic) || notifyTopic === topic))) throw new Error('Codice non valido');
  return { topic, notifyTopic, parentSpki: raw.slice(keyAt) };
}

async function hmac(keyBytes, data) {
  const k = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
async function expand(prk, info, length) {
  return (await hmac(prk, concat(enc.encode(info), new Uint8Array([1])))).slice(0, length);
}
/**
 * Same as SecureLink.derive: secret = ECDH x-coordinate, salt = SHA-256("tutela-link-v1:" + topic),
 * PRK = HMAC(salt, secret), keys = HKDF-Expand(PRK, "c2p"/"p2c", 32), code = HKDF-Expand(PRK, "verify", 4) mod 10^6.
 */
export async function derive(myPrivate, theirPublic, topic) {
  const secret = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: theirPublic }, myPrivate, 256));
  const salt = new Uint8Array(await subtle.digest('SHA-256', enc.encode('tutela-link-v1:' + topic)));
  const prk = await hmac(salt, secret);
  secret.fill(0);
  const c2pRaw = await expand(prk, 'c2p', 32), p2cRaw = await expand(prk, 'p2c', 32), v = await expand(prk, 'verify', 4);
  const mailboxAuth = b64(await expand(prk, 'mbox-auth', 32)); // 0.16: pair secret for writing to the mailbox server
  const n = ((v[0] << 24) >>> 0) + (v[1] << 16) + (v[2] << 8) + v[3];
  const aes = raw => subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { c2p: await aes(c2pRaw), p2c: await aes(p2cRaw), verification: String(n % 1000000).padStart(6, '0'), c2pRaw, p2cRaw, mailboxAuth };
}

export function peek(wire) {
  if (typeof wire !== 'string' || !wire.startsWith(WIRE_PREFIX)) throw new Error('Non è un messaggio Phylax');
  const raw = unb64(wire.slice(WIRE_PREFIX.length));
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  if (raw[0] !== WIRE_VERSION) throw new Error('Versione non supportata');
  const len = dv.getUint16(2);
  if (len > 200) throw new Error('Intestazione non valida');
  const childKey = raw.slice(4, 4 + len);
  const counter = Number(dv.getBigInt64(4 + len));
  return { direction: raw[1], childKey, counter, headerLen: 4 + len + 8, raw };
}
/** Opens a message of the expected direction; rejects tampering (GCM) and counters <= lastCounter. */
export async function open(key, expectedDirection, wire, lastCounter) {
  const h = peek(wire);
  if (h.direction !== expectedDirection) throw new Error('Direzione inattesa');
  if (h.counter <= lastCounter) throw new Error('Messaggio ripetuto (replay)');
  if (h.raw.length < h.headerLen + 12 + 16) throw new Error('Messaggio troncato');
  const iv = h.raw.slice(h.headerLen, h.headerLen + 12);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: h.raw.slice(0, h.headerLen), tagLength: 128 },
    key, h.raw.slice(h.headerLen + 12));
  return { header: h, plaintext: new Uint8Array(plain) };
}
export async function seal(key, direction, childKey, counter, plaintext) {
  const ck = childKey || new Uint8Array(0);
  const header = new Uint8Array(4 + ck.length + 8);
  const dv = new DataView(header.buffer);
  header[0] = WIRE_VERSION; header[1] = direction; dv.setUint16(2, ck.length);
  header.set(ck, 4);
  dv.setBigInt64(4 + ck.length, BigInt(counter));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, plaintext));
  return WIRE_PREFIX + b64(concat(header, iv, ct));
}
export function nextCounter(last, nowWall) { return Math.max(last + 1, nowWall); }

// ---- LinkMessage (plaintext format version 1), as in LinkMessage.java ----
export function decodeMessage(raw) {
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  let o = 0;
  const u8 = () => dv.getUint8(o++);
  const i8 = () => dv.getInt8(o++);
  const str = () => { const n = dv.getUint16(o); o += 2; if (o + n > raw.length) throw new Error('Troncato'); const s = dec.decode(raw.slice(o, o + n)); o += n; return s; };
  if (u8() !== 1) throw new Error('Formato non supportato');
  const t = i8();
  if (t < 0 || t >= TYPES.length) throw new Error('Tipo sconosciuto');
  const m = { type: TYPES[t] };
  m.time = Number(dv.getBigInt64(o)); o += 8;
  m.level = i8(); m.caseId = dv.getInt32(o); o += 4; m.outcome = i8();
  const s = i8();
  if (s < 0 || s >= STATES.length) throw new Error('Stato sconosciuto');
  m.state = STATES[s]; m.heartbeat = u8() !== 0;
  m.category = str(); m.app = str(); m.text = str();
  const n = dv.getInt16(o); o += 2;
  if (n < 0 || n > 200) throw new Error('Troppi frammenti');
  m.fragments = [];
  for (let i = 0; i < n; i++) m.fragments.push(str());
  if (o !== raw.length) throw new Error('Byte in eccesso');
  return m;
}
export function encodeMessage(m) {
  const strs = [m.category || '', m.app || '', m.text || ''].map(s => enc.encode(s));
  const frags = (m.fragments || []).map(s => enc.encode(s));
  const size = 1 + 1 + 8 + 1 + 4 + 1 + 1 + 1 + strs.reduce((n, s) => n + 2 + s.length, 0) + 2 + frags.reduce((n, s) => n + 2 + s.length, 0);
  const out = new Uint8Array(size), dv = new DataView(out.buffer);
  let o = 0;
  out[o++] = 1; out[o++] = TYPES.indexOf(m.type);
  dv.setBigInt64(o, BigInt(m.time)); o += 8;
  dv.setInt8(o++, m.level || 0); dv.setInt32(o, m.caseId || 0); o += 4; dv.setInt8(o++, m.outcome || 0);
  out[o++] = STATES.indexOf(m.state || 'ACTIVE'); out[o++] = m.heartbeat ? 1 : 0;
  for (const s of strs) { dv.setUint16(o, s.length); o += 2; out.set(s, o); o += s.length; }
  dv.setInt16(o, frags.length); o += 2;
  for (const s of frags) { dv.setUint16(o, s.length); o += 2; out.set(s, o); o += s.length; }
  return out;
}
export function closeMessage(time, caseId, outcome) { return encodeMessage({ type: 'CLOSE_CASE', time, caseId, outcome }); }

// ---- 0.22: screen time (same text lines as ScreenRules.java) ----
/** rules = { version, night: [start, end] | null (minutes of the day), limits: [{ pkg, label, minutes }] (0 = blocked),
 *  0.23: sites: ['ADULT', 'GAMBLING', 'VIOLENCE'], allow: [domain], deny: [domain] } */
/** 0.29: limit value for «Bloccata» (line «lock|pkg|label»): cannot be opened, no «15 minuti in più». */
export const LOCKED = -2;
export const SITE_CATEGORIES = [['ADULT', 'Siti per adulti'], ['GAMBLING', 'Scommesse e casinò'], ['VIOLENCE', 'Violenza estrema']];
export function rulesLines(r) {
  const out = [];
  if (r.night && r.night[0] !== r.night[1]) out.push('night|' + r.night[0] + '|' + r.night[1]);
  if (r.school && r.school.days && r.school.end > r.school.start) out.push('school|' + r.school.days + '|' + r.school.start + '|' + r.school.end);
  for (const l of r.limits || []) {
    const label = String(l.label || l.pkg).replace(/\|/g, ' ').trim().slice(0, 40) || l.pkg;
    out.push(l.minutes === LOCKED ? 'lock|' + l.pkg + '|' + label : 'limit|' + l.pkg + '|' + l.minutes + '|' + label);
  }
  for (const [c] of SITE_CATEGORIES) if ((r.sites || []).includes(c)) out.push('site|' + c);
  for (const d of r.allow || []) out.push('allow|' + d);
  for (const d of r.deny || []) out.push('deny|' + d);
  for (const p of r.places || []) out.push('place|' + p.lat.toFixed(5) + '|' + p.lon.toFixed(5) + '|' + p.radius + '|' + p.name);
  return out;
}
/** 0.24: same checks as ScreenRules.setPlace. Returns the cleaned place or null. */
export function makePlace(name, lat, lon, radius) {
  let n = String(name || '').replace(/\|/g, ' ').trim().slice(0, 40).trim().slice(0, 30);
  lat = Number(lat); lon = Number(lon); radius = Number(radius);
  if (!n || !Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180 || !Number.isFinite(radius)) return null;
  return { name: n, lat: Math.round(lat * 1e5) / 1e5, lon: Math.round(lon * 1e5) / 1e5, radius: Math.max(100, Math.min(1000, Math.round(radius))) };
}
/** Adds or replaces by name (at most 10 places). */
export function setPlace(list, p) {
  if (!p) return list;
  const has = list.some(x => x.name === p.name);
  if (!has && list.length >= 10) return list;
  return has ? list.map(x => x.name === p.name ? p : x) : [...list, p];
}
/** Same as ScreenRules.setLimit: minutes, 0 = in pause today, LOCKED = blocked, other negative = no limit (removed). */
export function setLimit(limits, pkg, label, minutes) {
  if (!pkg || pkg.includes('|')) return limits;
  const rest = (limits || []).filter(l => l.pkg !== pkg);
  if (minutes < 0 && minutes !== LOCKED) return rest;
  if (rest.length === (limits || []).length && rest.length >= 60) return limits;
  const label2 = String(label || pkg).replace(/\|/g, ' ').trim().slice(0, 40) || pkg;
  const item = { pkg, label: label2, minutes: minutes === LOCKED ? LOCKED : Math.min(minutes, 1440) };
  const i = (limits || []).findIndex(l => l.pkg === pkg);
  if (i < 0) return [...rest, item];
  const out = [...limits]; out[i] = item; return out;
}
/** 0.29: APPS fragments «label|package» -> [{ label, pkg }]. */
export function parseApps(fragments) {
  const out = [];
  for (const f of fragments || []) {
    const cut = f.lastIndexOf('|');
    if (cut <= 0 || cut === f.length - 1 || out.length >= 200) continue;
    const pkg = f.slice(cut + 1);
    if (!out.some(a => a.pkg === pkg)) out.push({ label: f.slice(0, cut), pkg });
  }
  return out;
}
export function askAppsMessage(time) { return encodeMessage({ type: 'APPS', time }); }
export function parseRules(version, lines) {
  const r = { version, night: null, school: null, limits: [], sites: [], allow: [], deny: [], places: [] };
  for (const line of lines || []) {
    const f = line.split('|');
    if (f[0] === 'night' && f.length >= 3) {
      const a = parseInt(f[1], 10), b = parseInt(f[2], 10);
      if (a >= 0 && a < 1440 && b >= 0 && b < 1440) r.night = [a, b];
    } else if (f[0] === 'school' && f.length >= 4) { // 0.27: days as bits (Monday = 1), minutes of the day
      const d = parseInt(f[1], 10) & 127, a = parseInt(f[2], 10), b = parseInt(f[3], 10);
      if (d > 0 && a >= 0 && b <= 1440 && b > a) r.school = { days: d, start: a, end: b };
    } else if (f[0] === 'limit' && f.length >= 3 && f[1]) {
      const m = parseInt(f[2], 10);
      if (m >= 0) r.limits = setLimit(r.limits, f[1], f.slice(3).join('|') || f[1], Math.min(m, 1440));
    } else if (f[0] === 'lock' && f.length >= 2 && f[1]) { // 0.29
      r.limits = setLimit(r.limits, f[1], f.slice(2).join('|') || f[1], LOCKED);
    } else if (f[0] === 'place' && f.length >= 5) {
      r.places = setPlace(r.places, makePlace(f.slice(4).join('|'), f[1], f[2], parseInt(f[3], 10)));
    } else if (f[0] === 'site' && SITE_CATEGORIES.some(([c]) => c === f[1]) && !r.sites.includes(f[1])) r.sites.push(f[1]);
    else if ((f[0] === 'allow' || f[0] === 'deny') && siteHost(f[1])) {
      const d = siteHost(f[1]);
      r.allow = r.allow.filter(x => x !== d); r.deny = r.deny.filter(x => x !== d);
      const list = f[0] === 'allow' ? r.allow : r.deny;
      if (list.length < 100) list.push(d);
    }
  }
  return r;
}
/** Same as SiteFilter.host: «https://www.Example.com/x» → «example.com», or null. */
export function siteHost(typed) {
  let v = String(typed || '').trim().toLowerCase();
  if (!v || v.includes(' ')) return null;
  const i = v.indexOf('://'); if (i >= 0) v = v.slice(i + 3);
  v = v.split(/[/?#:]/)[0];
  const at = v.lastIndexOf('@'); if (at >= 0) v = v.slice(at + 1);
  v = v.replace(/\.+$/, '');
  if (!v.includes('.') || v.startsWith('.') || !/^[a-z0-9.\-]+$/.test(v)) return null;
  return v.startsWith('www.') ? v.slice(4) : v;
}
export function rulesMessage(time, r) { return encodeMessage({ type: 'RULES', time, caseId: r.version, fragments: rulesLines(r) }); }
export function extraMessage(time, pkg, label, minutes, outcome) {
  return encodeMessage({ type: 'EXTRA', time, text: pkg, app: label, caseId: minutes, outcome });
}
export function locateMessage(time, request) { return encodeMessage({ type: 'LOCATION', time, caseId: request, outcome: LOC_ASK }); }
/** LOC_HERE text -> { lat, lon, meters, fixTime } or null. */
export function parseWhere(text) {
  const f = String(text || '').split(',');
  if (f.length !== 4) return null;
  const lat = Number(f[0]), lon = Number(f[1]), meters = parseInt(f[2], 10), fixTime = Number(f[3]);
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180 || !Number.isFinite(fixTime)) return null;
  return { lat, lon, meters: meters || 0, fixTime };
}
/** USAGE fragments «label|minutes|package» -> [{ label, minutes, pkg }]. */
/** 0.28: weekly summary (WeekSummary.java): d|day|min, p|prevTotal|prevDays, a|label|min|pkg|before, c|kind|count|before. */
export function parseWeek(weekStart, lines) {
  const w = { weekStart: weekStart || '', days: [-1, -1, -1, -1, -1, -1, -1], prevTotal: -1, prevDays: 0, apps: [], kinds: [] };
  const n = v => { const x = parseInt(v, 10); return Number.isFinite(x) ? Math.max(0, x) : null; };
  for (const line of lines || []) {
    const f = String(line).split('|');
    if (f[0] === 'd' && f.length >= 3) { const i = parseInt(f[1], 10), v = n(f[2]); if (i >= 0 && i < 7 && v !== null) w.days[i] = v; }
    else if (f[0] === 'p' && f.length >= 3) { const t = n(f[1]), d = n(f[2]); if (t !== null && d !== null) { w.prevTotal = t; w.prevDays = Math.min(7, d); } }
    else if (f[0] === 'a' && f.length >= 5 && w.apps.length < 10) { const m = n(f[2]), b = n(f[4]); if (m !== null && b !== null) w.apps.push({ label: f[1], minutes: m, pkg: f[3], before: b }); }
    else if (f[0] === 'c' && f.length >= 4 && w.kinds.length < 12) { const c = n(f[2]), b = n(f[3]); if (c !== null && b !== null) w.kinds.push({ category: f[1], count: c, before: b }); }
  }
  const known = w.days.filter(d => d >= 0);
  w.total = known.reduce((s, d) => s + d, 0);
  w.average = known.length ? Math.round(w.total / known.length) : -1;
  const prevAvg = w.prevTotal < 0 || !w.prevDays ? -1 : Math.round(w.prevTotal / w.prevDays);
  w.trend = w.average < 0 || prevAvg <= 0 ? null : Math.round(100 * (w.average - prevAvg) / prevAvg);
  w.alerts = w.kinds.reduce((s, k) => s + k.count, 0);
  w.alertsBefore = w.kinds.reduce((s, k) => s + k.before, 0);
  w.topKind = (w.kinds.find(k => k.count > 0) || {}).category || null;
  return w;
}
export function trendWord(pct) {
  if (pct === null || pct === undefined) return '';
  if (Math.abs(pct) < 5) return 'come la settimana prima';
  return (pct > 0 ? '+' : '−') + Math.abs(pct) + '% rispetto alla settimana prima';
}
export function parseUsage(fragments) {
  return (fragments || []).map(f => { const p = f.split('|'); return { label: p[0] || p[2], minutes: parseInt(p[1], 10) || 0, pkg: p[2] || p[0] }; });
}

// ---- 0.16: our mailbox server (worker/, Cloudflare): same sealed texts, kept 7 days. '' = not used. ----
export const MAILBOX = 'https://phylax-mailbox.phylax-mailbox.workers.dev';
/** SHA-256("phylax-mbox-v1:" + topic + ":c2p"|":p2c") in hex, as SecureLink.mailbox: the server never sees the topic. */
export async function mailboxName(topic, dir) {
  const d = new Uint8Array(await subtle.digest('SHA-256', enc.encode('phylax-mbox-v1:' + topic + ':' + dir)));
  return [...d].map(b => b.toString(16).padStart(2, '0')).join('');
}
export async function mailboxPost(box, auth, body) {
  const r = await fetch(MAILBOX + '/v1/m/' + box, { method: 'POST', body, headers: { 'Content-Type': 'text/plain', Authorization: 'Bearer ' + auth } });
  if (!r.ok) throw new Error('casella ' + r.status);
}
/** { messages: [{id, t, msg}], next } — oldest first, at most 100 after `since`. */
export async function mailboxPoll(box, since) {
  const r = await fetch(MAILBOX + '/v1/m/' + box + '?since=' + (Number(since) || 0), { cache: 'no-store' });
  if (!r.ok) throw new Error('casella ' + r.status);
  const j = await r.json();
  return { messages: Array.isArray(j.messages) ? j.messages.filter(m => typeof m.msg === 'string' && Number.isSafeInteger(m.id)) : [], next: Number(j.next) || Number(since) || 0 };
}

