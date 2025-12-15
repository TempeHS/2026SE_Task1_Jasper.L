const addr = window.STATIC_ADDRESS | "";

const assets = [
  addr + "/",
  addr + "css/style.css",
  addr + "css/bootstrap.min.css",
  addr + "js/bootstrap.bundle.min.js",
  addr + "js/app.js",
  addr + "images/logo.png",
  addr + "images/favicon.jpg",
  addr + "icons/icon-128x128.png",
  addr + "icons/icon-192x192.png",
  addr + "icons/icon-384x384.png",
  addr + "icons/icon-512x512.png",
  addr + "icons/desktop_screenshot.png",
  addr + "icons/mobile_screenshot.png",
];

const CATALOGUE_ASSETS = "catalogue-assets";

self.addEventListener("install", (installEvt) => {
  installEvt.waitUntil(
    caches
      .open(CATALOGUE_ASSETS)
      .then((cache) => {
        console.log(cache);
        cache.addAll(assets);
      })
      .then(self.skipWaiting())
      .catch((e) => {
        console.log(e);
      })
  );
});

self.addEventListener("activate", function (evt) {
  evt.waitUntil(
    caches
      .keys()
      .then((keyList) => {
        return Promise.all(
          keyList.map((key) => {
            if (key === CATALOGUE_ASSETS) {
              console.log("Removed old cache from", key);
              return caches.delete(key);
            }
          })
        );
      })
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", function (evt) {
  evt.respondWith(
    fetch(evt.request).catch(() => {
      return caches.open(CATALOGUE_ASSETS).then((cache) => {
        return cache.match(evt.request);
      });
    })
  );
});
