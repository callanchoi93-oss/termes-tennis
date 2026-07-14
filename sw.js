/* MATSU 서비스워커 v0714-J
   원칙: index.html(내비게이션)은 항상 네트워크 우선 — 재배포가 즉시 반영된다.
         오프라인일 때만 캐시 사본을 쓴다. 푸시 수신은 그대로 유지. */
const CACHE = 'matsu-v0714J';

self.addEventListener('install', (e) => {
  self.skipWaiting();                       // 대기 없이 즉시 새 워커로
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));  // 옛 캐시 전부 폐기
    await self.clients.claim();             // 열려 있는 탭도 즉시 이 워커가 담당
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  // 내비게이션(HTML) = 네트워크 우선, 실패 시에만 캐시 (오프라인 대비)
  if (req.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')) {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(req, { cache: 'no-store' });
        const c = await caches.open(CACHE);
        c.put(req, fresh.clone());
        return fresh;
      } catch (_) {
        const hit = await caches.match(req);
        return hit || new Response('오프라인이에요', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }
    })());
    return;
  }

  // API 는 손대지 않는다
  if (url.pathname.startsWith('/api') || url.pathname.startsWith('/auth') || url.pathname.startsWith('/uploads')) return;

  // 그 외 정적 자원 = 캐시 우선 + 백그라운드 갱신
  e.respondWith((async () => {
    const hit = await caches.match(req);
    const refresh = fetch(req).then(res => {
      if (res && res.ok) caches.open(CACHE).then(c => c.put(req, res.clone()));
      return res;
    }).catch(() => null);
    return hit || refresh || fetch(req);
  })());
});

/* ── 웹푸시 수신 (기존 기능 보존) ── */
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) {}
  const title = d.title || '맞수';
  e.waitUntil(self.registration.showNotification(title, {
    body: d.body || '',
    icon: d.icon || '/icon-192.png',
    badge: d.badge || '/icon-192.png',
    data: { link: d.link || '/' },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const link = (e.notification.data && e.notification.data.link) || '/';
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) { if ('focus' in c) { c.focus(); c.postMessage({ notifLink: link }); return; } }
    await self.clients.openWindow(link);
  })());
});
