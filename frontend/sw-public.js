// Service worker for the public, no-login LLA Land Registry page (public.html).
// Scope: makes the public summary installable and usable with no/weak connectivity -
// caches the app shell up front, and serves the last-known summary data when offline.
const CACHE = "lla-public-v3";
// Same-origin files only. Chart.js used to load from a CDN - a cross-origin request that
// could fail to cache (CORS) and used to fail the ENTIRE install, which meant nothing was
// ever cached and the app broke offline. It's now vendored locally (/vendor/chart.umd.min.js)
// so it's just another same-origin file that caches exactly as reliably as the rest.
const SHELL = [
  "/public.html",
  "/manifest.public.json",
  "/assets/icon-192.png",
  "/assets/icon-512.png",
  "/vendor/chart.umd.min.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) =>
      // Cache each file independently so one failure can't sink the whole install - every
      // resource that CAN be cached gets cached, instead of all-or-nothing.
      Promise.allSettled(SHELL.map((path) => cache.add(path)))
    ).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET") return;

  // The live summary: try the network first (so numbers stay fresh whenever there's a
  // connection), fall back to whatever was last cached when there isn't one.
  if (url.pathname === "/api/public/summary") {
    event.respondWith(
      fetch(event.request)
        .then((resp) => {
          if (resp.ok) {
            const copy = resp.clone();
            caches.open(CACHE).then((cache) => cache.put(event.request, copy));
          }
          return resp;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }

  // App shell + static assets: cache-first, so the page itself always opens instantly and
  // works offline, refreshing the cached copy in the background when online.
  if (SHELL.some((path) => url.pathname === path)) {
    event.respondWith(
      caches.match(event.request).then((cached) => {
        const network = fetch(event.request)
          .then((resp) => {
            if (resp.ok) caches.open(CACHE).then((cache) => cache.put(event.request, resp.clone()));
            return resp;
          })
          .catch(() => cached);
        return cached || network;
      })
    );
    return;
  }

  // Everything else (e.g. the Chart.js CDN script): opportunistically cache it the first
  // time it loads successfully, so it's still available next time even with no connection.
  // Cross-origin responses are often "opaque" (status can't be checked) - cache them anyway,
  // since a fetch that didn't throw at least reached the network.
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) {
        fetch(event.request).then((resp) => {
          caches.open(CACHE).then((cache) => cache.put(event.request, resp));
        }).catch(() => {});
        return cached;
      }
      return fetch(event.request).then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        return resp;
      }).catch(() => cached);
    })
  );
});
