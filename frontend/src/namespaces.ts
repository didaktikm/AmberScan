import { ApiError } from "./api";
import type {
  Cluster,
  Coverage,
  NamespaceDiscovery,
  NamespaceOption,
} from "./types";
import { parseNamespaces } from "./utils";

export const MAX_NAMESPACES = 100;
const SYSTEM_NAMESPACES = new Set([
  "kube-system",
  "kube-public",
  "kube-node-lease",
]);
export const isSystemNamespace = (name: string) => SYSTEM_NAMESPACES.has(name);
export const namespaceOptions = (names: string[]): NamespaceOption[] =>
  names.map((name) => ({ name, system: isSystemNamespace(name) }));

export function selectedNamespaces(
  values: string[],
  allowlist?: string[],
): string[] {
  const parsed = parseNamespaces(values.join("\n"));
  if (
    parsed.length !== values.length ||
    parsed.some((name, index) => name !== values[index])
  )
    throw new Error("Выберите разные корректные имена пространств имён.");
  if (allowlist && parsed.some((name) => !allowlist.includes(name)))
    throw new Error(
      "Выбор должен быть подмножеством сохранённых пространств имён. Снимите выбор с больше не разрешённых имён.",
    );
  return parsed;
}

export function addNamespaces(
  selected: string[],
  additions: string[],
  allowlist?: string[],
) {
  return selectedNamespaces(
    [...new Set([...selected, ...additions])],
    allowlist,
  );
}

/** Fail closed: historical/unstructured or all-denied coverage is never permission. */
export function coverageOutcome(
  coverage?: Coverage[],
): "unchecked" | "allowed" | "partial" | "failed" {
  if (!coverage) return "unchecked";
  if (!coverage.length) return "failed";
  const allowed = (row: Coverage) =>
    row.code === "allowed" && row.status === "completed";
  const denied = (row: Coverage) =>
    row.code === "http_403" && row.status === "denied";
  if (coverage.every(allowed)) return "allowed";
  if (
    coverage.some(allowed) &&
    coverage.every((row) => allowed(row) || denied(row))
  )
    return "partial";
  return "failed";
}

export function clusterAccessKey(cluster?: Cluster): string {
  return JSON.stringify(
    cluster && [
      cluster.id,
      cluster.lifecycle,
      cluster.auth_type,
      cluster.credential_kind,
      cluster.access_revision,
      cluster.namespaces,
      cluster.status,
      cluster.credential_expires_at,
      cluster.storage_mode,
    ],
  );
}

export function namespaceDiscovery(value: unknown): NamespaceDiscovery {
  const invalid = () =>
    new ApiError(
      "Сервер вернул некорректный список пространств имён. Пустой или успешный список не подтверждён.",
      0,
      "invalid_response",
    );
  if (!value || typeof value !== "object") throw invalid();
  const result = value as NamespaceDiscovery;
  if (
    !["complete", "partial", "forbidden"].includes(result.status) ||
    typeof result.complete !== "boolean" ||
    result.complete !== (result.status === "complete") ||
    !Array.isArray(result.items) ||
    result.items.length > 1000 ||
    (result.continuation != null &&
      (typeof result.continuation !== "string" ||
        !result.continuation ||
        result.continuation.length > 65536 ||
        result.status !== "partial")) ||
    (result.status === "forbidden" && result.items.length > 0) ||
    (result.limitation !== null && typeof result.limitation !== "string")
  )
    throw invalid();
  const names = new Set<string>();
  for (const row of result.items) {
    if (
      !row ||
      typeof row.name !== "string" ||
      row.name.length > 63 ||
      !/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(row.name) ||
      names.has(row.name) ||
      typeof row.system !== "boolean" ||
      (row.phase != null && typeof row.phase !== "string")
    )
      throw invalid();
    names.add(row.name);
  }
  return result;
}

export function preflightCoverage(value: unknown): Coverage[] {
  if (
    !value ||
    typeof value !== "object" ||
    !("coverage" in value) ||
    !Array.isArray(value.coverage) ||
    value.coverage.some(
      (row: unknown) =>
        !row ||
        typeof row !== "object" ||
        !("check" in row) ||
        typeof row.check !== "string" ||
        !("status" in row) ||
        typeof row.status !== "string" ||
        !("detail" in row) ||
        typeof row.detail !== "string",
    )
  )
    throw new ApiError(
      "Сервер вернул некорректное покрытие. Повторите проверку доступа.",
      0,
      "invalid_response",
    );
  return value.coverage;
}

export function namespaceError(error: unknown): ApiError {
  return error instanceof ApiError
    ? error
    : new ApiError(
        error instanceof Error ? error.message : "Не удалось выполнить запрос.",
      );
}

export function needsKubernetesAuthorization(error?: ApiError) {
  return (
    !!error &&
    [
      "kubernetes_authentication_required",
      "credential_missing",
      "credential_expired",
      "authorization_required",
    ].includes(error.code)
  );
}

/** Only the server's fixed, non-privileged draft identifier is resumable. No URLs or tokens. */
export function connectionDraftId(hash: string): string | undefined {
  return /^#connection-draft=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(
    hash,
  )?.[1];
}

export function clearConnectionDraftHash() {
  if (connectionDraftId(window.location.hash))
    window.history.replaceState(
      null,
      "",
      window.location.pathname + window.location.search,
    );
}
