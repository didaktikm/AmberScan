import { useEffect, useRef, useState, type FormEvent } from "react";
import { CredentialRecovery, useRecoveredCluster } from "./CredentialRecovery";
import { Play } from "lucide-react";
import { api } from "./api";
import { credentialValid } from "./utils";
import { Modal, Notice } from "./ui";
import { NamespacePicker } from "./NamespacePicker";
import {
  NamespaceCoverage,
  NamespaceError,
  UnsupportedClusterScope,
  useNamespaceAccess,
} from "./NamespaceAccess";
import {
  clusterAccessKey,
  namespaceError,
  namespaceOptions,
  selectedNamespaces,
} from "./namespaces";
import type { Cluster, Run } from "./types";

export function RunLaunch({
  clusters,
  initialCluster,
  onClose,
  onCreated,
}: {
  clusters: Cluster[];
  initialCluster?: string;
  onClose: () => void;
  onCreated: (run: Run) => void;
}) {
  const [clusterId, setClusterId] = useState(initialCluster ?? "");
  // Resolve by id every render, never retain an obsolete Cluster object after reload.
  const source = clusters.find(
    (item) => item.id === clusterId && item.lifecycle === "ready",
  );
  const [cluster, setRecoveredCluster] = useRecoveredCluster(source);
  const [recovering, setRecovering] = useState(false);
  const access = useNamespaceAccess(cluster);
  const [timeout, setTimeoutValue] = useState(300);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const key = clusterAccessKey(cluster);
  const currentKey = useRef(key);
  currentKey.current = key;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const valid =
    cluster?.status === "authorized" &&
    credentialValid(cluster.credential_expires_at);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!cluster || !valid || !access.canProceed || busy) return;
    setBusy(true);
    access.setError(undefined);
    try {
      const namespaces = selectedNamespaces(
        access.selected,
        cluster.namespaces,
      );
      if (!Number.isInteger(timeout) || timeout < 10 || timeout > 600)
        throw new Error("Лимит времени должен быть от 10 до 600 секунд.");
      const result = await api<Run>("/runs", {
        method: "POST",
        body: { cluster_id: cluster.id, namespaces, timeout_seconds: timeout },
      });
      if (alive.current && currentKey.current === key) onCreated(result);
    } catch (reason) {
      if (alive.current && currentKey.current === key) {
        access.invalidate();
        access.setError(namespaceError(reason));
      }
    } finally {
      if (alive.current) setBusy(false);
    }
  }
  return (
    <Modal
      wide
      title="Запустить проверку"
      subtitle="Встроенный аудит конфигурации только на чтение. Внешний сканер командной строки не запускается."
      onClose={onClose}
      busy={busy || recovering}
    >
      <form onSubmit={submit} className="form-stack">
        <NamespaceError error={access.error} />
        <label>
          Кластер
          <select
            required
            value={clusterId}
            disabled={busy || recovering}
            onChange={(event) => {
              access.change([]);
              setClusterId(event.target.value);
            }}
          >
            <option value="">Выберите кластер</option>
            {clusters
              .filter((item) => item.lifecycle === "ready")
              .map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {item.environment}
                </option>
              ))}
          </select>
        </label>
        {!cluster && clusterId && (
          <Notice tone="warning">
            Подключение недоступно или ещё является черновиком. Запуск запрещён.
          </Notice>
        )}
        {cluster && (
          <>
            <Notice>
              Контекст: <strong>{cluster.context}</strong>
              <br />
              <span className="break-word">{cluster.server}</span>
            </Notice>
            {!valid && (
              <Notice tone="warning">
                Нет действующей личной авторизации. Повторно импортируйте
                kubeconfig перед запуском.
              </Notice>
            )}
            <CredentialRecovery
              cluster={cluster}
              disabled={busy || recovering || !!access.busy}
              onBusyChanged={setRecovering}
              onUpdated={(value) => {
                access.invalidate(true);
                setRecoveredCluster(value);
              }}
            />
            <NamespacePicker
              label="Область проверки"
              selected={access.selected}
              onChange={access.change}
              options={namespaceOptions(cluster.namespaces)}
              allowlist={cluster.namespaces}
              hint={cluster.namespace_hint}
              disabled={busy}
            />
            <button
              type="button"
              className="button button-secondary"
              disabled={
                busy || !!access.busy || !valid || !access.selected.length
              }
              onClick={() => void access.preflight().catch(() => {})}
            >
              {access.busy === "preflight"
                ? "Проверяем выбранные пространства имён…"
                : "Проверить выбранные пространства имён"}
            </button>
            <NamespaceCoverage
              coverage={access.coverage}
              acceptPartial={access.acceptPartial}
              onAcceptPartial={access.setAcceptPartial}
            />
            <label>
              Лимит времени, секунд
              <input
                type="number"
                required
                min={10}
                max={600}
                value={timeout}
                disabled={busy}
                onChange={(event) =>
                  setTimeoutValue(Number(event.target.value))
                }
              />
              <small>
                От 10 до 600 секунд. Ожидание очереди показывается отдельно от
                выполнения.
              </small>
            </label>
          </>
        )}
        <Notice tone="warning">
          Проверка не читает Secrets, ConfigMaps, логи и не выполняет команды.
          Недоступные ресурсы будут показаны как пробелы покрытия, а не как
          успешные проверки.
        </Notice>
        <UnsupportedClusterScope />
        <div className="modal-footer">
          <button
            className="button button-secondary"
            type="button"
            disabled={busy}
            onClick={onClose}
          >
            Отмена
          </button>
          <button
            className="button button-primary"
            type="submit"
            disabled={
              busy || !!access.busy || !cluster || !valid || !access.canProceed
            }
          >
            <Play size={16} />
            {busy ? "Создание запуска…" : "Запустить проверку"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
