import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorText } from "./api";

export function useResource<T>(path: string | null, pollMs = 0) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const currentPath = useRef(path);
  const reload = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    if (path === null) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    if (currentPath.current !== path) {
      setData(undefined);
      currentPath.current = path;
    }
    setLoading(true);
    setError(undefined);
    void api<T>(path, { signal: controller.signal })
      .then((result) => {
        if (!controller.signal.aborted) setData(result);
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) setError(errorText(reason));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, revision]);
  useEffect(() => {
    if (!pollMs || !path) return;
    const interval = setInterval(() => {
      if (!document.hidden) reload();
    }, pollMs);
    return () => clearInterval(interval);
  }, [path, pollMs, reload]);
  return { data, setData, error, loading, reload };
}

export function useClock(active = false) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!active) return;
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [active]);
  return now;
}
