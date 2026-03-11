const CACHE_NAME = 'vpn-pwa-cache-v1';
const urlsToCache = [
  './',
  './index.html',
  './manifest.json'
];

// Установка кэша
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

// Перехват запросов
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Возвращаем кэшированный ответ, если есть, иначе идем в сеть
        if (response) {
          return response;
        }
        return fetch(event.request);
      }
    )
  );
});
