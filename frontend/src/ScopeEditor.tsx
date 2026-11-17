import { useEffect, useRef, useState } from "react";
import { CredentialRecovery, useRecoveredCluster } from "./CredentialRecovery";
import { api } from "./api";
import { AdminConfirmation } from "./AdminConfirmation";
import { NamespacePicker } from "./NamespacePicker";
import {
  NamespaceCoverage,
  NamespaceError,
  UnsupportedClusterScope,
  useNamespaceAccess,
} from "./NamespaceAccess";
import { namespaceError, selectedNamespaces } from "./namespaces";
import { Definition, Modal, Notice } from "./ui";
import { credentialValid } from "./utils";
import type { Cluster, ScopeResult } from "./types";

export function ScopeEditor({
  cluster: source,
  onClose,
  onChanged,
}: {
  cluster: Cluster;
  onClose: () => void;
  onChanged: (cluster: Cluster) => void;
}) {
  const [recovered, setRecoveredCluster] = useRecoveredCluster(source);
  const cluster = recovered!;
  const [recovering, setRecovering] = useState(false);
  const access = useNamespaceAccess(cluster!, true);
  const [baseRevision] = useState(cluster.access_revision);
  const [confirm, setConfirm] = useState<"preflight" | "save">();
  const [until, setUntil] = useState<string>();
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const changed = baseRevision !== cluster.access_revision;
  const valid =
    cluster.lifecycle === "ready" &&
    cluster.status === "authorized" &&
    credentialValid(cluster.credential_expires_at);
  async function save() {
    if (!access.canProceed || changed)
      throw new Error(
        "Область или доступ изменились. Повторите проверку доступа для актуального подключения.",
      );
    try {
      const result = await api<ScopeResult>(
        `/clusters/${encodeURIComponent(cluster.id)}/scope`,
        {
          method: "PATCH",
          body: {
            namespaces: selectedNamespaces(access.selected),
            expected_access_revision: baseRevision,
            accept_partial: access.acceptPartial,
          },
        },
      );
      if (alive.current) onChanged(result.cluster);
    } catch (reason) {
      if (alive.current) {
        access.invalidate();
        access.setError(namespaceError(reason));
      }
      throw reason;
    }
  }
  return (
    <Modal
      wide
      title="Изменить разрешённые пространства имён"
      subtitle={cluster.name}
      onClose={onClose}
      busy={!!access.busy || !!confirm || recovering}
    >
      <div className="form-stack">
        <Notice>
          Это явное редактирование списка разрешённых пространств имён
          подключения, а не области одного запуска. Текущие сохранённые имена
          выбраны. Получение списка и его обновление ничего не сохраняют.
        </Notice>
        {changed && (
          <Notice tone="warning">
            Подключение изменилось в другой операции. Закройте редактор и
            откройте его заново, чтобы проверить актуальную область. Сохранение
            устаревшего выбора заблокировано.
          </Notice>
        )}
        {!valid && (
          <Notice tone="warning">
            Для проверки новой области нужна ваша действующая личная
            авторизация. Повторно импортируйте kubeconfig.
          </Notice>
        )}
        <CredentialRecovery
          cluster={cluster}
          disabled={changed || !!confirm || !!access.busy}
          onBusyChanged={setRecovering}
          onUpdated={(value) => {
            access.invalidate(true);
            setRecoveredCluster(value);
          }}
        />
        <NamespaceError error={access.error} />
        <NamespacePicker
          savedNames={cluster.namespaces}
          selected={access.selected}
          onChange={access.change}
          options={access.discovery?.items ?? []}
          loaded={!!access.discovery}
          stale={access.discoveryStale}
          complete={access.discovery?.complete ?? false}
          forbidden={access.discovery?.status === "forbidden"}
          limitation={access.discovery?.limitation}
          hint={cluster.namespace_hint}
          disabled={changed || recovering || !valid || !!confirm}
          loading={access.busy === "discovery"}
          onRefresh={() => void access.discover()}
          onLoadMore={
            access.discovery?.continuation && !access.discoveryStale
              ? () => void access.loadMore()
              : undefined
          }
        />
        <button
          type="button"
          className="button button-secondary"
          disabled={
            changed || !valid || !!access.busy || !access.selected.length
          }
          onClick={() => setConfirm("preflight")}
        >
          Проверить новую область
        </button>
        <NamespaceCoverage
          coverage={access.coverage}
          acceptPartial={access.acceptPartial}
          onAcceptPartial={access.setAcceptPartial}
        />
        <UnsupportedClusterScope />
        <div className="modal-footer">
          <button
            type="button"
            className="button button-secondary"
            onClick={onClose}
          >
            Отмена
          </button>
          <button
            type="button"
            className="button button-primary"
            disabled={changed || !valid || !!access.busy || !access.canProceed}
            onClick={() => setConfirm("save")}
          >
            Сохранить новую область
          </button>
        </div>
      </div>
      {confirm && (
        <AdminConfirmation
          title={
            confirm === "save"
              ? "Сохранить область подключения"
              : "Проверить новую область подключения"
          }
          confirmLabel={
            confirm === "save"
              ? "Подтвердить и сохранить область"
              : "Подтвердить и проверить область"
          }
          initialUntil={until}
          onReauthenticated={setUntil}
          onClose={() => setConfirm(undefined)}
          onConfirm={async () => {
            if (changed)
              throw new Error(
                "Подключение изменилось. Закройте редактор и обновите данные.",
              );
            if (confirm === "save") await save();
            else {
              await access.preflight(true);
              if (alive.current) setConfirm(undefined);
            }
          }}
          warning={
            confirm === "save"
              ? "Сервер повторит проверку доступа и сравнит ревизию. Изменение списка разрешённых пространств имён отзывает личные авторизации всех пользователей и отменяет устаревшие задания. Сохранение без изменения области не отзывает доступ."
              : "Пробные GET-запросы только на чтение в выбранной новой области, включая добавленные имена. Область пока не изменяется."
          }
        >
          <Definition
            items={[
              ["Ревизия доступа", baseRevision],
              ["Выбрано", access.selected.join(", ")],
              [
                "Частичное покрытие",
                access.acceptPartial ? "Явно принято" : "Не принято",
              ],
            ]}
          />
        </AdminConfirmation>
      )}
    </Modal>
  );
}
