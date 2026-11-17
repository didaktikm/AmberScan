import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "./api";
import {
  clusterAccessKey,
  coverageOutcome,
  namespaceDiscovery,
  namespaceError,
  needsKubernetesAuthorization,
  preflightCoverage,
  selectedNamespaces,
} from "./namespaces";
import { CoverageTable, ErrorBox, Notice } from "./ui";
import type { Cluster, Coverage, NamespaceDiscovery } from "./types";

/** Request fences also protect against fetch implementations that ignore AbortSignal. */
export function useNamespaceAccess(cluster?: Cluster, editing = false) {
  const [selected, setSelected] = useState<string[]>(
    editing ? (cluster?.namespaces ?? []) : [],
  );
  const [discovery, setDiscovery] = useState<NamespaceDiscovery>();
  const [discoveryStale, setDiscoveryStale] = useState(false);
  const [coverage, setCoverage] = useState<Coverage[]>();
  const [acceptPartial, setAcceptPartial] = useState(false);
  const [error, setError] = useState<ApiError>();
  const [busy, setBusy] = useState<"discovery" | "preflight">();
  const generation = useRef(0);
  const controller = useRef<AbortController | undefined>(undefined);
  const key = clusterAccessKey(cluster);
  const currentKey = useRef(key);
  currentKey.current = key;
  const previousId = useRef(cluster?.id);
  function invalidate(resetDiscovery = false) {
    if (resetDiscovery) {
      setDiscovery(undefined);
      setDiscoveryStale(false);
    }
    generation.current += 1;
    controller.current?.abort();
    setBusy(undefined);
    setCoverage(undefined);
    setAcceptPartial(false);
    setError(undefined);
  }
  useEffect(() => {
    invalidate();
    setDiscovery(undefined);
    setDiscoveryStale(false);
    if (previousId.current !== cluster?.id) {
      setSelected(editing ? (cluster?.namespaces ?? []) : []);
      previousId.current = cluster?.id;
    }
    return () => {
      generation.current += 1;
      controller.current?.abort();
    };
  }, [key]);
  function change(names: string[]) {
    invalidate();
    setSelected(names);
  }
  function begin(kind: "discovery" | "preflight") {
    invalidate();
    const attempt = generation.current;
    const accessKey = key;
    const abort = new AbortController();
    controller.current = abort;
    setBusy(kind);
    return {
      signal: abort.signal,
      current: () =>
        !abort.signal.aborted &&
        generation.current === attempt &&
        currentKey.current === accessKey,
    };
  }
  async function discover(append = false) {
    if (!cluster || (append && (!discovery?.continuation || discoveryStale)))
      return;
    const previous = append ? discovery : undefined;
    const request = begin("discovery");
    setDiscoveryStale(!!discovery);
    try {
      const result = await api<NamespaceDiscovery>(
        `/clusters/${encodeURIComponent(cluster.id)}/namespaces/discover`,
        {
          method: "POST",
          body: previous ? { continuation: previous.continuation } : {},
          signal: request.signal,
        },
      );
      if (request.current()) {
        const batch = namespaceDiscovery(result);
        setDiscovery(
          previous
            ? {
                ...batch,
                items: [
                  ...new Map(
                    [...previous.items, ...batch.items].map((row) => [
                      row.name,
                      row,
                    ]),
                  ).values(),
                ].sort((a, b) => a.name.localeCompare(b.name)),
              }
            : batch,
        );
        setDiscoveryStale(false);
      }
    } catch (reason) {
      if (request.current()) {
        setError(namespaceError(reason));
        // Never append to an unconfirmed snapshot, even after a transient failure.
        setDiscoveryStale(!!discovery);
      }
    } finally {
      if (request.current()) setBusy(undefined);
    }
  }
  async function preflight(proposedScope = false) {
    if (!cluster) return;
    const request = begin("preflight");
    try {
      const namespaces = selectedNamespaces(
        selected,
        cluster.lifecycle === "ready" && !proposedScope
          ? cluster.namespaces
          : undefined,
      );
      const result = await api<{ coverage: Coverage[] }>(
        `/clusters/${encodeURIComponent(cluster.id)}/${proposedScope ? "scope/preflight" : "preflight"}`,
        { method: "POST", body: { namespaces }, signal: request.signal },
      );
      if (request.current()) setCoverage(preflightCoverage(result));
    } catch (reason) {
      if (request.current()) {
        setError(namespaceError(reason));
        throw reason;
      }
    } finally {
      if (request.current()) setBusy(undefined);
    }
  }
  const outcome = coverageOutcome(coverage);
  return {
    selected,
    change,
    discovery,
    discoveryStale,
    coverage,
    acceptPartial,
    setAcceptPartial,
    error,
    setError,
    busy,
    discover,
    loadMore: () => discover(true),
    preflight,
    invalidate,
    outcome,
    canProceed:
      outcome === "allowed" || (outcome === "partial" && acceptPartial),
  };
}

export function NamespaceError({ error }: { error?: ApiError }) {
  return (
    <>
      <ErrorBox message={error?.message} />
      {needsKubernetesAuthorization(error) && (
        <Notice tone="warning">
          Kubernetes отклонил личные учётные данные. Повторно импортируйте
          kubeconfig через кнопку восстановления доступа. Ваша сессия AmberData
          не завершена.
        </Notice>
      )}
      {error &&
        [
          "namespace_snapshot_expired",
          "invalid_namespace_continuation",
        ].includes(error.code) && (
          <Notice tone="warning">
            Снимок списка истёк или изменился. Нажмите «Обновить список»: новый
            список заменит старый, выбор останется явным.
          </Notice>
        )}
      {error &&
        [
          "http_tls",
          "tls_error",
          "http_network",
          "http_transport",
          "http_dns",
          "network_error",
          "http_timeout",
          "timeout",
          "egress_denied",
          "endpoint_denied",
        ].includes(error.code) && (
          <Notice tone="warning">
            Список и доступ не подтверждены. Ошибка сети, TLS или политики не
            означает пустой кластер и не допускает частичное подтверждение.
          </Notice>
        )}
    </>
  );
}

export function NamespaceCoverage({
  coverage,
  acceptPartial,
  onAcceptPartial,
}: {
  coverage?: Coverage[];
  acceptPartial?: boolean;
  onAcceptPartial?: (value: boolean) => void;
}) {
  if (!coverage) return null;
  const outcome = coverageOutcome(coverage);
  return (
    <section className="form-stack" aria-label="Результат проверки доступа">
      <h3>Доступ к выбранным пространствам имён</h3>
      <p className="small muted">
        Пробные GET-запросы к ресурсам (до одного объекта на тип). Это проверка
        чтения, не полный аудит и не подтверждение существования вручную
        введённых имён.
      </p>
      <CoverageTable coverage={coverage} />
      {coverage.some(
        (row) =>
          row.code === "http_401" ||
          row.code === "kubernetes_authentication_required",
      ) && (
        <Notice tone="warning">
          Kubernetes отклонил учётные данные. Повторно импортируйте kubeconfig{" "}
          подключения, затем повторите проверку доступа. Ваша сессия AmberData
          не завершена.
        </Notice>
      )}
      {outcome === "partial" && (
        <Notice tone="warning">
          Часть чтений запрещена RBAC (403). Есть доступные чтения, но покрытие
          будет неполным. Проверьте конкретные ресурсы выше.
        </Notice>
      )}
      {outcome === "partial" && onAcceptPartial && (
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={!!acceptPartial}
            onChange={(event) => onAcceptPartial(event.target.checked)}
          />
          <span>Принимаю частичное покрытие выбранной области</span>
        </label>
      )}
      {outcome === "failed" && (
        <Notice tone="warning">
          Продолжение заблокировано: нет подтверждённого доступа либо есть
          ошибки, отличные от частичного RBAC 403. Исправьте причину и повторите
          проверку доступа.
        </Notice>
      )}
    </section>
  );
}

export function UnsupportedClusterScope() {
  return (
    <Notice>
      Кластерные проверки не поддерживаются и не включены: Nodes, ClusterRoles и
      другие ресурсы уровня кластера не обследуются. Доступен только встроенный
      сбор сведений о ресурсах в пространствах имён; внешние профили
      сканирования не запускаются.
    </Notice>
  );
}
