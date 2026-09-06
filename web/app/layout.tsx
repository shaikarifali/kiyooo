import type { Metadata } from "next";
import "./globals.css";
import { Nav } from "@/components/Nav";

export const metadata: Metadata = {
  title: "kiyooo",
  description: "AI-triaged Attack Surface Management",
};

// The demo target range runs as its own process/port on purpose (kiyoo-ai/
// acmecorp/kiyoo-range simulate infrastructure this tool scans — sharing
// an origin with the real product would mean a fake attack target and
// your actual session living under the same cookies). This link is the
// one-click answer instead: always visible, right in the header, so
// nobody needs to remember or type a port for it.
const LABS_URL = process.env.NEXT_PUBLIC_LABS_URL ?? "http://localhost:9900";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <a className="brand" href="/dashboard">
            <span className="brand-mark">K</span>
            <span className="brand-text">
              kiyoo<span className="accent">oo</span>
            </span>
          </a>
          <nav className="topbar-links">
            <a href="/dashboard">Dashboard</a>
            <a href="/scope">Scope</a>
            <a href="/docs">API docs</a>
            <a href={LABS_URL} target="_blank" rel="noreferrer">
              Labs ↗
            </a>
          </nav>
          <div className="topbar-meta">
            <span className="pill">AI-triaged ASM</span>
            <span className="pill pill-live">live</span>
          </div>
        </header>
        <div className="layout">
          <Nav />
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
