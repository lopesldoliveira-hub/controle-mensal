// Mantido simples: permite instalar o app e deixa todas as telas e dados vindos da internet.
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('fetch', function () {});
