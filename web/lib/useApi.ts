"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiError } from "./api";

type State<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
};

/** Fetches on mount and whenever `deps` change; exposes `refetch` for
 * mutation-triggered reloads (e.g. after submitting a review). */
export function useApi<T>(fn: () => Promise<T>, deps: React.DependencyList = []): State<T> & {
  refetch: () => void;
} {
  const [state, setState] = useState<State<T>>({ data: null, loading: true, error: null });
  const [tick, setTick] = useState(0);

  const load = useCallback(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));
    fn()
      .then((data) => {
        if (!cancelled) setState({ data, loading: false, error: null });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const message = err instanceof ApiError ? err.message : String(err);
        setState({ data: null, loading: false, error: message });
      });
    return () => {
      cancelled = true;
    };
  }, // eslint-disable-next-line react-hooks/exhaustive-deps
  [...deps, tick]);

  useEffect(() => load(), [load]);

  return { ...state, refetch: () => setTick((t) => t + 1) };
}
