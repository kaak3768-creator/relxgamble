RELX GAMBLE MONEY (versi server) 

File yang harus ada di GitHub/Vercel:
  index.html, style.css, app.js
  api/index.js   <- backend (wajib)

Environment Variables di Vercel:
  KV_REST_API_URL, KV_REST_API_TOKEN  (otomatis dari Storage > Upstash Redis)
  ADMIN_PASSWORD                      (password admin, buat sendiri)

Setelah semua file ada, deploy ulang (Redeploy).
