// Offline app shell only. Never caches ntfy.sh (alerts are rebuilt from the ciphertext at each opening).
const CACHE = 'phylax-genitore-0.12';
const SHELL = ['./', 'index.html', 'style.css', 'app.js', 'link.js', 'bio.js', 'manifest.json',
  'icons/icon.svg', 'icons/shield.svg', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL.map(u => new Request(u, { cache: 'reload' })))).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin) return; // ntfy: straight to the network
  // Network first, revalidating with the server (updates arrive at once), cache when offline.
  e.respondWith(fetch(e.request, { cache: 'no-cache' }).then(r => {
    if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
    return r;
  }).catch(() => caches.match(e.request, { ignoreSearch: true }).then(r => r || caches.match('index.html'))));
});
// Web Push from the child's phone: only a fixed text (encrypted by the sender, decrypted by the browser).
// First text = default. The old Tutela texts stay accepted while a child phone still runs 0.10.x.
const PUSH_TEXTS = ["Nuovo avviso da Phylax: apri l'app", 'Phylax: notifiche attive', "Nuovo avviso da Tutela: apri l'app", 'Tutela: notifiche attive'];
self.addEventListener('push', e => {
  let body = PUSH_TEXTS[0];
  try { const t = e.data && e.data.text(); if (PUSH_TEXTS.includes(t)) body = t; } catch { /* keep the fixed text */ }
  e.waitUntil(Promise.all([
    self.registration.showNotification('Phylax Genitore', { body, tag: 'tutela', icon: 'icons/icon-192.png' }),
    self.navigator.setAppBadge ? self.navigator.setAppBadge().catch(() => {}) : Promise.resolve(),
  ]));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window' }).then(list => list.length ? list[0].focus() : self.clients.openWindow('./')));
});
