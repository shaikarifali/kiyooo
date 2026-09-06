"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ModuleKey } from "@/lib/types";
import { isModuleEnabled, useModuleToggles } from "@/lib/useModuleToggles";

const LINKS: { href: string; label: string; module?: ModuleKey }[] = [
  { href: "/", label: "Change feed" },
  { href: "/scope", label: "Scope" },
  { href: "/ingest", label: "Ingest" },
  { href: "/cloud", label: "Cloud posture", module: "cloud" },
  { href: "/containers", label: "Containers", module: "containers" },
  { href: "/repos", label: "Repos", module: "repos" },
  { href: "/mobile", label: "Mobile", module: "mobile" },
  { href: "/ai-surface", label: "AI attack surface" },
  { href: "/attack-paths", label: "Attack paths", module: "attack_paths" },
  { href: "/triage", label: "Triage queue" },
  { href: "/assets", label: "Asset explorer" },
  { href: "/coverage", label: "Coverage" },
  { href: "/scan-runs", label: "Scan runs" },
  { href: "/categories", label: "Categories" },
  { href: "/models", label: "Model configuration" },
  { href: "/settings", label: "Settings" },
  { href: "/dashboard", label: "Dashboard" },
];

export function Nav() {
  const pathname = usePathname();
  const { enabledMap, loading } = useModuleToggles();

  return (
    <div className="sidebar">
      <nav>
        {LINKS.filter(
          (link) => !link.module || isModuleEnabled(enabledMap, link.module, loading),
        ).map((link) => {
          const active =
            link.href === "/" ? pathname === "/" : pathname?.startsWith(link.href);
          return (
            <Link key={link.href} href={link.href} className={active ? "active" : ""}>
              <span className="dot" />
              {link.label}
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
