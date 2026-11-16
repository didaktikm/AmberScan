import { useEffect, useRef, useState } from "react";
import {
  Boxes,
  ChevronRight,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Upload,
} from "lucide-react";
import { api, errorText } from "../api";
import { useResource } from "../hooks";
import {
  Badge,
  Definition,
  EmptyState,
  ErrorBox,
  Modal,
  Notice,
  PageHeader,
  Panel,
  Spinner,
} from "../ui";
import { canManage, canScan, credentialValid, formatDate } from "../utils";
import { RunLaunch } from "../RunLaunch";
import { AdminConfirmation } from "../AdminConfirmation";
import { ClusterWizard } from "../ConnectionWizard";
export { ClusterWizard } from "../ConnectionWizard";
import { NamespacePicker } from "../NamespacePicker";
import {
  NamespaceCoverage,
  NamespaceError,
  UnsupportedClusterScope,
  useNamespaceAccess,
} from "../NamespaceAccess";
import {
  clearConnectionDraftHash,
  clusterAccessKey,
  namespaceOptions,
} from "../namespaces";
import { CredentialRecovery, useRecoveredCluster } from "../CredentialRecovery";
import { ScopeEditor } from "../ScopeEditor";
import type { Capabilities, Cluster, User } from "../types";

export function ClusterDetail({
  cluster: source,
  user,
  onClose,
  onChanged,
  onLaunch,
}: {
  cluster: Cluster;
  user: User;
  onClose: () => void;
  onChanged: () => void;
  onLaunch: () => void;
}) {
  const [recovered, setRecoveredCluster] = useRecoveredCluster(source);
  const cluster = recovered!;
  const [recovering, setRecovering] = useState(false);
  const access = useNamespaceAccess(cluster);
  const [editingScope, setEditingScope] = useState(false);
  const actionGeneration = useRef(0);
  const accessKey = clusterAccessKey(cluster);
  const currentKey = useRef(accessKey);
  currentKey.current = accessKey;
  useEffect(
    () => () => {
      actionGeneration.current += 1;
    },
    [accessKey],
  );
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [revoking, setRevoking] = useState<"personal" | "all">();
  const [revoked, setRevoked] = useState<"personal" | "all">();
  const valid =
    cluster.lifecycle === "ready" &&
    !revoked &&
    cluster.status === "authorized" &&
    credentialValid(cluster.credential_expires_at);
  async function revoke(scope: "personal" | "all") {
    const attempt = ++actionGeneration.current;
    access.invalidate();
    setBusy("revoke");
    setError(undefined);
    try {
      await api(
        `/clusters/${encodeURIComponent(cluster.id)}/${scope === "personal" ? "authorization" : "credential"}`,
        {
          method: "DELETE",
        },
      );
      if (
        attempt !== actionGeneration.current ||
        currentKey.current !== accessKey
      )
        return;
      setRevoking(undefined);
      setRevoked(scope);
      access.invalidate();
      onChanged();
    } catch (reason) {
      if (attempt !== actionGeneration.current) return;
      if (scope === "all") throw reason; // The protected confirmation handles reauthentication errors.
      setError(errorText(reason));
    } finally {
      if (attempt === actionGeneration.current) setBusy(undefined);
    }
  }
  return (
    <Modal
      wide
      title={cluster.name}
      subtitle="Метаданные подключения, ваша личная авторизация и проверка разрешений"
      onClose={onClose}
      busy={!!busy || recovering}
    >
      <div className="form-stack">
        <div className="detail-badges">
          <Badge value={revoked ? "authorization_required" : cluster.status} />
          <span className="tag">{cluster.environment}</span>
          <span className="tag">Kubeconfig</span>
        </div>
        <ErrorBox message={error} />
        <Definition
          items={[
            ["Контекст", cluster.context],
            ["Адрес API", cluster.server],
            ["Создан", formatDate(cluster.created_at)],
            [
              "Хранение вашей авторизации",
              revoked
                ? "Отозвана"
                : cluster.storage_mode === "run_only"
                  ? "На один запуск в этой локальной сессии"
                  : cluster.storage_mode === "persistent"
                    ? "На сервере до истечения срока или отзыва"
                    : "Не передано сервером",
            ],
            [
              "Личный доступ в приложении до",
              revoked
                ? "Удалён из консоли"
                : formatDate(cluster.credential_expires_at),
            ],
            [
              "Пространства имён",
              <div className="tag-list">
                {cluster.namespaces.map((namespace) => (
                  <span key={namespace} className="tag">
                    {namespace}
                  </span>
                ))}
              </div>,
            ],
          ]}
        />
        {revoked && (
          <Notice tone="success">
            {revoked === "all"
              ? "Авторизации всех пользователей этого кластера отозваны в консоли."
              : "Ваша личная авторизация отозвана в консоли. Авторизации других пользователей не изменены."}{" "}
            Связанные ожидающие задания отменены, для активных запрошена отмена.
            Это не отзывает исходные учётные данные в Kubernetes.
          </Notice>
        )}
        {canScan(user.role) && (
          <>
            <div className="button-row">
              <CredentialRecovery
                cluster={cluster}
                disabled={!!busy || !!access.busy}
                onBusyChanged={setRecovering}
                onUpdated={(value) => {
                  access.invalidate(true);
                  setRevoked(undefined);
                  setRecoveredCluster(value);
                  onChanged();
                }}
              />
              <button
                className="button button-secondary"
                disabled={!!busy || !valid}
                onClick={onLaunch}
              >
                <Play size={16} />
                Запустить проверку
              </button>
            </div>
          </>
        )}
        <Notice>
          Авторизация личная: учётные данные не передаются другим участникам
          команды. Для каждого пользователя требуется отдельный импорт.
        </Notice>
        {!valid && (
          <Notice tone="warning">
            Ваша действующая авторизация не подтверждена. Повторно импортируйте
            kubeconfig.
          </Notice>
        )}
        {canScan(user.role) && (
          <section className="preflight-section">
            <div>
              <h3>Проверка доступа к ресурсам</h3>
              <p className="small muted">
                Пробные GET-запросы только на чтение для каждого пространства
                имён. Успех отдельной пробы не подтверждает полное покрытие
                аудита.
              </p>
            </div>
            <div className="form-stack">
              <NamespaceError error={access.error} />
              <NamespacePicker
                label="Пространства имён для проверки доступа"
                selected={access.selected}
                onChange={access.change}
                options={namespaceOptions(cluster.namespaces)}
                allowlist={cluster.namespaces}
                hint={cluster.namespace_hint}
                disabled={!!busy || !valid}
              />
              <div>
                <button
                  className="button button-secondary"
                  type="button"
                  disabled={
                    !!busy || !!access.busy || !valid || !access.selected.length
                  }
                  onClick={() => void access.preflight().catch(() => {})}
                >
                  <ShieldCheck size={16} />
                  {access.busy === "preflight"
                    ? "Проверяем разрешения…"
                    : "Проверить доступ"}
                </button>
              </div>
              <NamespaceCoverage coverage={access.coverage} />
            </div>
            <UnsupportedClusterScope />
          </section>
        )}
        {canManage(user.role) && cluster.lifecycle === "ready" && (
          <section className="preflight-section form-stack">
            <h3>Разрешённая область подключения</h3>
            <p className="small muted">
              Отдельное административное действие с подтверждением пароля и
              актуальной проверкой доступа. Изменение области отзывает старый
              доступ.
            </p>
            <div>
              <button
                type="button"
                className="button button-secondary"
                disabled={!!busy}
                onClick={() => {
                  access.invalidate();
                  setEditingScope(true);
                }}
              >
                Изменить пространства имён подключения
              </button>
            </div>
          </section>
        )}
        {editingScope && (
          <ScopeEditor
            cluster={cluster}
            onClose={() => setEditingScope(false)}
            onChanged={() => {
              setEditingScope(false);
              access.invalidate();
              onChanged();
            }}
          />
        )}
        {canScan(user.role) && !revoked && (
          <section className="revoke-section form-stack">
            <div>
              <h3>Ваша личная авторизация</h3>
              <p className="small muted">
                Отзыв закрывает также ваши активные задания в этом кластере.
                Других пользователей не затрагивает.
              </p>
            </div>
            {revoking === "personal" ? (
              <>
                <Notice tone="warning">
                  Отозвать только вашу авторизацию и отменить ваши задания в
                  этом кластере? Исходные учётные данные автоматически не
                  отзываются.
                </Notice>
                <div className="button-row">
                  <button
                    className="button button-danger"
                    disabled={!!busy}
                    onClick={() => void revoke("personal")}
                  >
                    {busy === "revoke"
                      ? "Отзываем…"
                      : "Подтвердить личный отзыв"}
                  </button>
                  <button
                    className="button button-secondary"
                    disabled={!!busy}
                    onClick={() => setRevoking(undefined)}
                  >
                    Оставить
                  </button>
                </div>
              </>
            ) : (
              <div>
                <button
                  className="button button-secondary"
                  disabled={!!busy}
                  onClick={() => setRevoking("personal")}
                >
                  <ShieldOff size={15} />
                  Отозвать мою авторизацию
                </button>
              </div>
            )}
          </section>
        )}
        {canManage(user.role) && revoked !== "all" && (
          <section className="revoke-section form-stack">
            <div>
              <h3>Административный отзыв для всего кластера</h3>
              <p className="small muted">
                Отдельное действие для всех пользователей. Требует подтверждения
                пароля администратора.
              </p>
            </div>
            <div>
              <button
                className="text-button danger-text"
                disabled={!!busy}
                onClick={() => setRevoking("all")}
              >
                <ShieldOff size={15} />
                Отозвать авторизации всех пользователей
              </button>
            </div>
          </section>
        )}
        {revoking === "all" && canManage(user.role) && (
          <AdminConfirmation
            title="Отозвать доступ ко всему кластеру"
            confirmLabel="Отозвать все авторизации"
            danger
            onClose={() => setRevoking(undefined)}
            onConfirm={() => revoke("all")}
            warning="Будут отозваны авторизации всех пользователей этого кластера. Ожидающие задания будут отменены, для активных запрошена отмена. Это не отзывает исходные учётные данные в Kubernetes."
          >
            <Definition
              items={[
                ["Кластер", cluster.name],
                ["Адрес API", cluster.server],
                ["Область отзыва", "Все пользователи этого кластера"],
              ]}
            />
          </AdminConfirmation>
        )}
      </div>
    </Modal>
  );
}

export function ClustersPage({
  user,
  openRun,
  resumeDraftId,
  onResumeHandled,
}: {
  user: User;
  openRun: (id: string) => void;
  resumeDraftId?: string;
  onResumeHandled?: () => void;
}) {
  const clusters = useResource<Cluster[]>("/clusters");
  const drafts = useResource<Cluster[]>(
    canManage(user.role) ? "/cluster-drafts" : null,
  );
  const capabilities = useResource<Capabilities>("/capabilities");
  const [wizard, setWizard] = useState(!!resumeDraftId && canManage(user.role));
  const [draftId, setDraftId] = useState(resumeDraftId);
  const [selectedId, setSelectedId] = useState<string>();
  const selected = clusters.data?.find(
    (cluster) => cluster.id === selectedId && cluster.lifecycle === "ready",
  );
  useEffect(() => {
    if (resumeDraftId && canManage(user.role)) {
      setDraftId(resumeDraftId);
      setWizard(true);
    }
  }, [resumeDraftId, user.role]);
  function closeWizard() {
    setWizard(false);
    setDraftId(undefined);
    clearConnectionDraftHash();
    onResumeHandled?.();
    drafts.reload();
  }
  const [launch, setLaunch] = useState<string>();
  const [created, setCreated] = useState(false);
  function refresh() {
    clusters.reload();
    capabilities.reload();
    drafts.reload();
  }
  return (
    <>
      <PageHeader
        title="Кластеры"
        description="Явные подключения, области пространств имён и личная авторизация через kubeconfig."
        action={
          <div className="button-row">
            <button className="button button-secondary" onClick={refresh}>
              <RefreshCw size={16} />
              Обновить
            </button>
            {canManage(user.role) && (
              <button
                className="button button-primary"
                onClick={() => {
                  setCreated(false);
                  setDraftId(undefined);
                  setWizard(true);
                }}
              >
                <Plus size={17} />
                Подключить кластер
              </button>
            )}
          </div>
        }
      />
      <ErrorBox message={clusters.error} retry={clusters.reload} />
      <ErrorBox message={capabilities.error} retry={capabilities.reload} />
      {created && (
        <Notice tone="success">
          Подключение готово. Явно выбранная область сохранена после проверки
          доступа. Для запуска выберите нужное подмножество отдельно.
        </Notice>
      )}
      {canManage(user.role) && (
        <Panel
          title="Мои черновики"
          action={
            <button
              type="button"
              className="text-button"
              onClick={drafts.reload}
            >
              Обновить черновики
            </button>
          }
        >
          <ErrorBox message={drafts.error} retry={drafts.reload} />
          {drafts.loading && !drafts.data ? (
            <Spinner label="Загружаем ваши черновики…" />
          ) : drafts.data?.length ? (
            <div className="draft-list">
              {drafts.data.map((draft) => (
                <div className="draft-row" key={draft.id}>
                  <div>
                    <strong>{draft.name}</strong>
                    <p className="small muted">
                      {draft.context} · {draft.server}
                    </p>
                    <p className="small muted">
                      Действует до {formatDate(draft.draft_expires_at)}. Не
                      готов к запуску.
                    </p>
                  </div>
                  <button
                    type="button"
                    className="button button-secondary"
                    onClick={() => {
                      setDraftId(draft.id);
                      setWizard(true);
                    }}
                  >
                    Продолжить подключение {draft.name}
                  </button>
                </div>
              ))}
            </div>
          ) : (
            drafts.data && (
              <p className="small muted">
                Незавершённых подключений нет. Закрытый мастер сохраняет только
                ваш серверный черновик, не исходный kubeconfig.
              </p>
            )
          )}
        </Panel>
      )}
      {!canManage(user.role) && (
        <Notice>
          Добавление подключений, настройки исходящих подключений и отзыв
          доступа всех пользователей доступны администратору. Аудиторы и
          руководители ИБ могут отдельно отозвать свою личную авторизацию. Видны
          только разрешённые вам кластеры.
        </Notice>
      )}
      {clusters.loading && !clusters.data ? (
        <Spinner />
      ) : clusters.data?.length ? (
        <Panel
          title="Подключения"
          action={
            <span className="small muted">{clusters.data.length} доступно</span>
          }
        >
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Кластер</th>
                  <th>Контекст / адрес API</th>
                  <th>Область</th>
                  <th>Личный доступ в приложении до</th>
                  <th>Состояние</th>
                  <th>
                    <span className="sr-only">Действия</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {clusters.data
                  .filter((cluster) => cluster.lifecycle === "ready")
                  .map((cluster) => (
                    <tr key={cluster.id}>
                      <td>
                        <button
                          className="table-link"
                          onClick={() => setSelectedId(cluster.id)}
                        >
                          {cluster.name}
                          <span>{cluster.environment}</span>
                        </button>
                      </td>
                      <td>
                        <span className="cell-primary break-word">
                          {cluster.context}
                        </span>
                        <span className="cell-subtext endpoint">
                          {cluster.server}
                        </span>
                      </td>
                      <td>
                        <div className="tag-list">
                          {cluster.namespaces.slice(0, 3).map((namespace) => (
                            <span className="tag" key={namespace}>
                              {namespace}
                            </span>
                          ))}
                          {cluster.namespaces.length > 3 && (
                            <span className="tag">
                              +{cluster.namespaces.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="cell-secondary nowrap">
                        {formatDate(cluster.credential_expires_at)}
                      </td>
                      <td>
                        <Badge value={cluster.status} />
                      </td>
                      <td>
                        <button
                          className="icon-button"
                          aria-label={`Открыть кластер ${cluster.name}`}
                          onClick={() => setSelectedId(cluster.id)}
                        >
                          <ChevronRight size={19} />
                        </button>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : (
        clusters.data && (
          <Panel title="Подключения">
            <EmptyState
              icon={<Boxes size={32} />}
              title="Нет доступных кластеров"
              action={
                canManage(user.role) ? (
                  <button
                    className="button button-primary"
                    onClick={() => setWizard(true)}
                  >
                    <Upload size={17} />
                    Импортировать kubeconfig
                  </button>
                ) : undefined
              }
            >
              {canManage(user.role)
                ? "Подключите кластер, выбрав контекст, способ авторизации и конкретные пространства имён. Полный доступ не запрашивается автоматически."
                : "Попросите администратора создать подключение и предоставить вам доступ. Отсутствие записей не означает, что в системе нет кластеров."}
            </EmptyState>
          </Panel>
        )
      )}
      <div className="page-footnote">
        <ShieldCheck size={16} />
        <p>
          Проверки используют сохранённый контекст и ограниченную область
          доступа. Исходный kubeconfig не хранится. Личные учётные данные
          выбранного контекста хранятся зашифрованно с ограниченным сроком.
        </p>
      </div>
      {wizard && (
        <ClusterWizard
          key={draftId ?? "new"}
          resumeId={draftId}
          onDraftChanged={drafts.reload}
          capabilities={capabilities.data}
          capabilitiesLoading={capabilities.loading}
          capabilitiesError={capabilities.error}
          reloadCapabilities={capabilities.reload}
          user={user}
          onClose={closeWizard}
          onCreated={(cluster) => {
            closeWizard();
            setCreated(true);
            clusters.reload();
            setSelectedId(cluster.id);
          }}
        />
      )}
      {selected && (
        <ClusterDetail
          key={selected.id}
          cluster={selected}
          user={user}
          onClose={() => setSelectedId(undefined)}
          onChanged={clusters.reload}
          onLaunch={() => {
            setLaunch(selected.id);
            setSelectedId(undefined);
          }}
        />
      )}
      {launch && (
        <RunLaunch
          clusters={clusters.data ?? []}
          initialCluster={launch}
          onClose={() => setLaunch(undefined)}
          onCreated={(run) => {
            setLaunch(undefined);
            openRun(run.id);
          }}
        />
      )}
    </>
  );
}
