"use client";

import { api } from "./api";
import type { ModuleKey } from "./types";
import { useApi } from "./useApi";

export type ModuleEnabledMap = Partial<Record<ModuleKey, boolean>>;

/** GET /api/module-toggles, reshaped into a lookup map. Every consumer
 * (Nav, ModuleGate, the Settings page) fetches independently rather than
 * sharing a cache — five small rows, no benefit to a store for this. */
export function useModuleToggles() {
  const { data, loading, error, refetch } = useApi(() => api.listModuleToggles(), []);
  const enabledMap: ModuleEnabledMap = {};
  for (const toggle of data ?? []) enabledMap[toggle.module_key] = toggle.enabled;
  return { toggles: data, enabledMap, loading, error, refetch };
}

/** Fails open (shows/allows) while loading or if a module has no row yet —
 * a backend hiccup or a pre-migration row gap should never silently hide a
 * module the user never chose to turn off. */
export function isModuleEnabled(
  enabledMap: ModuleEnabledMap,
  key: ModuleKey,
  loading: boolean,
): boolean {
  if (loading) return true;
  return enabledMap[key] ?? true;
}
