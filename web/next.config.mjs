// One origin for the whole product: the browser only ever talks to this
// app (whatever port `next dev`/`next start` is on) — this rewrite proxies
// /api/* server-side to the real FastAPI backend, so nobody using the UI
// ever needs to know the API has its own port. `NEXT_PUBLIC_API_BASE_URL`
// (already set correctly per-port by scripts/kiyoo) is read here, not by
// the browser — lib/api.ts's fetch calls are same-origin relative paths.
const API_PROXY_TARGET = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${API_PROXY_TARGET}/api/:path*` },
      // FastAPI's interactive docs, proxied same-origin too — "the API"
      // is reachable at one URL, not a second port nobody's supposed to
      // have to remember.
      { source: "/docs", destination: `${API_PROXY_TARGET}/docs` },
      { source: "/redoc", destination: `${API_PROXY_TARGET}/redoc` },
      { source: "/openapi.json", destination: `${API_PROXY_TARGET}/openapi.json` },
    ];
  },
};

export default nextConfig;
