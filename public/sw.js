/* MATSU 서비스워커
 *
 * 원칙 세 가지:
 *  1) API 요청은 절대 캐시하지 않는다. (회비·대진·점수는 항상 최신이어야 한다)
 *  2) HTML 은 네트워크 우선. 실패할 때만 캐시. (새 버전 배포가 바로 반영된다)
 *  3) 아이콘·폰트 같은 정적 파일만 캐시 우선.
 *
 * CACHE_VERSION 을 올리면 옛 캐시가 전부 지워진다. index.html 을 배포할 때 같이 올릴 것.
 */
const CACHE_VERSION = 'matsu-v2';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const HTML_CACHE = `${CACHE_VERSION}-html`;

const PRECACHE = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/apple-touch-icon.png',
];

// API 로 나가는 경로. 이 목록은 캐시하지 않고 항상 네트워크로 보낸다.
const API_PREFIXES = [
  '/config', '/diag',                        // 설정·진단은 절대 캐시하지 않는다
  '/health', '/auth', '/me', '/clubs', '/brackets', '/events', '/dues',
  '/dm', '/cash', '/posts', '/matches', '/open-matches', '/users',
  '/notifications', '/pay', '/iap', '/upload', '/admin', '/devices',
];
const isApi = (p) => API_PREFIXES.some((x) => p === x || p.startsWith(x + '/') || p.startsWith(x + '?'));

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(STATIC_CACHE)
      .then((c) => c.addAll(PRECACHE))
      .then(() => self.skipWaiting())          // 새 워커를 즉시 대기 상태로
      .catch(() => self.skipWaiting())         // 프리캐시 실패해도 설치는 진행
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => !k.startsWith(CACHE_VERSION)).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())        // 열려 있는 탭도 새 워커가 넘겨받는다
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;            // POST/PATCH/DELETE 는 건드리지 않는다

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;   // 외부 CDN 은 브라우저에 맡긴다
  if (isApi(url.pathname)) return;                   // API 는 통과

  // HTML: 네트워크 우선 → 실패 시 캐시 (오프라인)
  const wantsHtml = req.mode === 'navigate' ||
    (req.headers.get('accept') || '').includes('text/html');
  if (wantsHtml) {
    e.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(HTML_CACHE).then((c) => c.put('/', copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match('/').then((r) => r || caches.match(req)))
    );
    return;
  }

  // 정적 파일: 캐시 우선 → 없으면 네트워크로 받아 캐시
  e.respondWith(
    caches.match(req).then((hit) => hit || fetch(req).then((res) => {
      if (res && res.status === 200 && res.type === 'basic') {
        const copy = res.clone();
        caches.open(STATIC_CACHE).then((c) => c.put(req, copy)).catch(() => {});
      }
      return res;
    }))
  );
});

// 푸시 알림 (나중에 서버에서 web-push 로 보낼 때 쓴다)
self.addEventListener('push', (e) => {
  let d = { title: 'MATSU', body: '' };
  try { d = e.data ? e.data.json() : d; } catch (err) {}
  e.waitUntil(self.registration.showNotification(d.title || 'MATSU', {
    body: d.body || '',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    data: { url: d.url || '/' },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) if (c.url.includes(self.location.origin) && 'focus' in c) return c.focus();
      return self.clients.openWindow(target);
    })
  );
});
