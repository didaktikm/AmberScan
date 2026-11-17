import { useEffect, useRef, useState } from "react";
import {
  Boxes,
  ChevronRight,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
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
import {
  canManage,
  canScan,
  credentialValid,
  formatDate,
  stageLabels,
  statusLabels,
} from "../utils";
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
import type { Capabilities, Cluster, Run, User } from "../types";

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
  const [notice, setNotice] = useState<string>();
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
  async function chooseSchedule(kind: "periodic" | "watch" | "off") {
    const attempt = ++actionGeneration.current;
    setBusy("schedule");
    setError(undefined);
    setNotice(undefined);
    try {
      await api(`/clusters/${encodeURIComponent(cluster.id)}/schedule`, {
        method: "POST",
        body: { kind, confirm: true },
      });
      if (attempt !== actionGeneration.current) return;
      setNotice(
        kind === "off"
          ? "Расписание остановлено. Кластер не изменялся."
          : "Включена повторная проверка только на чтение. Кластер не изменяется.",
      );
    } catch (reason) {
      if (attempt !== actionGeneration.current) return;
      setError(errorText(reason));
    } finally {
      if (attempt === actionGeneration.current) setBusy(undefined);
    }
  }
  async function confirmProtected(
    action: "live_scanner" | "extended" | "operator" | "continuous",
  ) {
    const attempt = ++actionGeneration.current;
    setBusy(action);
    setError(undefined);
    setNotice(undefined);
    try {
      const result = await api<{ detail: string }>(
        `/clusters/${encodeURIComponent(cluster.id)}/protected-action`,
        { method: "POST", body: { action, confirm: true } },
      );
      if (attempt !== actionGeneration.current) return;
      setNotice(result.detail);
    } catch (reason) {
      if (attempt !== actionGeneration.current) return;
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
                    : cluster.storage_mode === "days_30"
                      ? "На сервере 30 дней или до отзыва"
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
        {notice && <Notice tone="success">{notice}</Notice>}
        {canScan(user.role) && cluster.lifecycle === "ready" && (
          <section className="form-stack">
            <h3>Повторные проверки</h3>
            <p className="small muted">
              Только чтение сохранённой области. Кластер не изменяется. Нужна
              авторизация на 30 дней: раз в сутки или не чаще чем раз в 6
              часов.
            </p>
            <div className="button-row">
              <button
                type="button"
                className="button button-secondary"
                disabled={!!busy}
                onClick={() => chooseSchedule("periodic")}
              >
                Раз в сутки
              </button>
              <button
                type="button"
                className="button button-secondary"
                disabled={!!busy}
                onClick={() => chooseSchedule("watch")}
              >
                Каждые 6 часов
              </button>
              <button
                type="button"
                className="button button-secondary"
                disabled={!!busy}
                onClick={() => chooseSchedule("off")}
              >
                Остановить
              </button>
            </div>
            <h3>Дополнительные проверки</h3>
            <p className="small muted">
              Сканеры не меняют кластер. Расширенная проверка и оператор
              меняют его и запускаются только этой кнопкой. Исправление
              отдельной находки подтверждается в карточке находки.
            </p>
            <div className="button-row">
              {(
                [
                  ["live_scanner", "Сканеры"],
                  ["extended", "Расширенные"],
                  ["operator", "Оператор"],
                  ["continuous", "Наблюдение"],
                ] as const
              ).map(([action, label]) => (
                <button
                  key={action}
                  type="button"
                  className="button button-secondary"
                  disabled={!!busy}
                  onClick={() => confirmProtected(action)}
                >
                  {label}
                </button>
              ))}
            </div>
          </section>
        )}
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

type LaunchLog = {
  key: string;
  at: string;
  cluster: string;
  title: string;
  message: string;
  runId?: string;
  status?: string;
  stage?: string;
};

const listActions = [
  ["live_scanner", "Сканеры"],
  ["extended", "Расширенные"],
  ["operator", "Оператор"],
  ["continuous", "Наблюдение"],
] as const;

export function ClustersPage({
  user,
  openRun,
  resumeDraftId,
  onResumeHandled,
  onOpenFindings,
}: {
  user: User;
  openRun: (id: string) => void;
  resumeDraftId?: string;
  onResumeHandled?: () => void;
  onOpenFindings?: (clusterId: string) => void;
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
  const [profileOpen, setProfileOpen] = useState(false);
  const [profileName, setProfileName] = useState("");
  const [profileEnvironment, setProfileEnvironment] = useState("");
  const [profileError, setProfileError] = useState<string>();
  const [profileBusy, setProfileBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [checked, setChecked] = useState<string[]>([]);
  const [logs, setLogs] = useState<LaunchLog[]>([]);
  const [actionBusy, setActionBusy] = useState<string>();
  const ready =
    clusters.data?.filter((cluster) => cluster.lifecycle === "ready") ?? [];
  const chosen = ready.filter((cluster) => checked.includes(cluster.id));
  useEffect(() => {
    const ids = new Set(
      (clusters.data ?? [])
        .filter((cluster) => cluster.lifecycle === "ready")
        .map((cluster) => cluster.id),
    );
    setChecked((current) => {
      const next = current.filter((id) => ids.has(id));
      return next.length === current.length ? current : next;
    });
  }, [clusters.data]);
  useEffect(() => {
    const pending = logs.filter(
      (item) =>
        item.runId &&
        (item.status === "queued" || item.status === "running" || !item.status),
    );
    if (!pending.length) return;
    const timer = window.setInterval(() => {
      void Promise.all(
        pending.map(async (item) => {
          const run = await api<Run>(`/runs/${encodeURIComponent(item.runId!)}`);
          return { id: item.runId!, run };
        }),
      )
        .then((updates) => {
          setLogs((current) => {
            let changed = false;
            const next = current.map((item) => {
              const update = updates.find((entry) => entry.id === item.runId);
              if (
                !update ||
                (update.run.status === item.status &&
                  update.run.stage === item.stage &&
                  (update.run.error || item.message) === item.message)
              )
                return item;
              changed = true;
              return {
                ...item,
                status: update.run.status,
                stage: update.run.stage,
                message: update.run.error || item.message,
              };
            });
            return changed ? next : current;
          });
        })
        .catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(timer);
  }, [logs]);
  function remember(entries: LaunchLog[]) {
    if (!entries.length) return;
    setLogs((current) => [...entries, ...current].slice(0, 40));
  }
  async function runOnChosen(
    action: "scan" | (typeof listActions)[number][0],
    title: string,
  ) {
    if (!chosen.length || actionBusy) return;
    setActionBusy(action);
    const entries: LaunchLog[] = [];
    for (const cluster of chosen) {
      const at = new Date().toISOString();
      try {
        if (action === "scan") {
          const run = await api<Run>("/runs", {
            method: "POST",
            body: {
              cluster_id: cluster.id,
              namespaces: cluster.namespaces,
              timeout_seconds: 300,
            },
          });
          entries.push({
            key: run.id,
            at,
            cluster: cluster.name,
            title,
            message: "Проверка поставлена в очередь. Кластер не изменяется.",
            runId: run.id,
            status: run.status,
            stage: run.stage,
          });
        } else {
          const result = await api<{
            detail: string;
            run_id?: string;
            status?: string;
          }>(`/clusters/${encodeURIComponent(cluster.id)}/protected-action`, {
            method: "POST",
            body: { action, confirm: true },
          });
          entries.push({
            key: result.run_id ?? `${cluster.id}-${at}`,
            at,
            cluster: cluster.name,
            title,
            message: result.detail,
            runId: result.run_id,
            status: result.status,
          });
        }
      } catch (reason) {
        entries.push({
          key: `${cluster.id}-${at}`,
          at,
          cluster: cluster.name,
          title,
          message: errorText(reason),
        });
      }
    }
    remember(entries);
    setActionBusy(undefined);
  }
  function refresh() {
    clusters.reload();
    capabilities.reload();
    drafts.reload();
  }
  function openAdd() {
    setCreated(false);
    setDraftId(undefined);
    setWizard(true);
  }
  function openProfile() {
    const cluster = chosen[0];
    if (!cluster) return;
    setProfileName(cluster.name);
    setProfileEnvironment(cluster.environment);
    setProfileError(undefined);
    setProfileOpen(true);
  }
  async function saveProfile() {
    const cluster = chosen[0];
    const name = profileName.trim();
    const environment = profileEnvironment.trim();
    if (!cluster || !name || !environment || profileBusy) return;
    setProfileBusy(true);
    setProfileError(undefined);
    try {
      await api(`/clusters/${encodeURIComponent(cluster.id)}`, {
        method: "PATCH",
        body: { name, environment },
      });
      setProfileOpen(false);
      refresh();
    } catch (reason) {
      setProfileError(errorText(reason));
    } finally {
      setProfileBusy(false);
    }
  }
  async function deleteChosen() {
    for (const cluster of chosen) {
      await api(`/clusters/${encodeURIComponent(cluster.id)}`, {
        method: "DELETE",
      });
    }
    setChecked([]);
    setDeleting(false);
    if (selectedId && chosen.some((cluster) => cluster.id === selectedId))
      setSelectedId(undefined);
    refresh();
  }
  const manageActions = canManage(user.role) ? (
    <>
      <button className="button button-primary" type="button" onClick={openAdd}>
        <Plus size={16} />
        Добавить
      </button>
      <button
        className="button button-secondary"
        type="button"
        disabled={chosen.length !== 1}
        onClick={openProfile}
      >
        <Pencil size={16} />
        Изменить
      </button>
      <button
        className="button button-danger"
        type="button"
        disabled={!chosen.length}
        onClick={() => setDeleting(true)}
      >
        <Trash2 size={16} />
        Удалить
      </button>
    </>
  ) : null;
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
              <button className="button button-primary" onClick={openAdd}>
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
      ) : clusters.data ? (
        <Panel
          title="Подключения"
          action={
            <div
              className="cluster-toolbar"
              aria-label="Действия с кластерами"
            >
              <span className="small muted">
                {ready.length} доступно
              </span>
              {manageActions}
            </div>
          }
        >
          {canScan(user.role) && ready.length > 0 && (
            <div className="cluster-toolbar cluster-toolbar-body">
              <span className="small muted">
                {chosen.length
                  ? `Выбрано: ${chosen.length}`
                  : "Отметьте кластеры галочками"}
              </span>
              <button
                type="button"
                className="button button-secondary"
                disabled={!chosen.length || !!actionBusy}
                onClick={() => void runOnChosen("scan", "Проверка")}
              >
                <Play size={16} />
                {actionBusy === "scan" ? "Запускаем…" : "Запустить проверку"}
              </button>
              {listActions.map(([action, label]) => (
                <button
                  key={action}
                  type="button"
                  className="button button-secondary"
                  disabled={!chosen.length || !!actionBusy}
                  onClick={() => void runOnChosen(action, label)}
                >
                  {actionBusy === action ? "Запускаем…" : label}
                </button>
              ))}
              <button
                type="button"
                className="button button-secondary"
                disabled={chosen.length !== 1}
                onClick={() => onOpenFindings?.(chosen[0].id)}
              >
                Уязвимости
              </button>
            </div>
          )}
          {ready.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      aria-label="Выбрать все кластеры"
                      checked={!!ready.length && chosen.length === ready.length}
                      onChange={(event) =>
                        setChecked(
                          event.target.checked
                            ? ready.map((cluster) => cluster.id)
                            : [],
                        )
                      }
                    />
                  </th>
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
                        <input
                          type="checkbox"
                          aria-label={`Выбрать кластер ${cluster.name}`}
                          checked={checked.includes(cluster.id)}
                          onChange={(event) =>
                            setChecked((current) =>
                              event.target.checked
                                ? [...current, cluster.id]
                                : current.filter((id) => id !== cluster.id),
                            )
                          }
                        />
                      </td>
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
          ) : (
            <EmptyState
              icon={<Boxes size={32} />}
              title="Нет доступных кластеров"
              action={
                canManage(user.role) ? (
                  <button className="button button-primary" onClick={openAdd}>
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
          )}
        </Panel>
      ) : null}
      {canScan(user.role) && (
        <Panel title="Журнал запусков">
          {logs.length ? (
            <ol className="activity-log">
              {logs.map((item) => (
                <li key={item.key}>
                  <strong>
                    {formatDate(item.at)} · {item.cluster} · {item.title}
                  </strong>
                  <span>
                    {item.status
                      ? `${statusLabels[item.status] ?? item.status}${item.stage ? ` · ${stageLabels[item.stage] ?? item.stage}` : ""}. `
                      : ""}
                    {item.message}
                  </span>
                  {item.runId && (
                    <button
                      type="button"
                      className="text-button"
                      onClick={() => openRun(item.runId!)}
                    >
                      Открыть запуск
                    </button>
                  )}
                </li>
              ))}
            </ol>
          ) : (
            <p className="small muted">
              Здесь появятся строки, когда проверка, сканеры или наблюдение
              будут поставлены в очередь.
            </p>
          )}
        </Panel>
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
      {profileOpen && chosen[0] && (
        <Modal
          title="Изменить кластер"
          subtitle="Меняются только название и окружение в приложении. Адрес API и кластер Kubernetes остаются прежними."
          onClose={() => {
            if (!profileBusy) setProfileOpen(false);
          }}
          busy={profileBusy}
        >
          <form
            className="form-stack"
            onSubmit={(event) => {
              event.preventDefault();
              void saveProfile();
            }}
          >
            <ErrorBox message={profileError} />
            <label>
              Название
              <input
                value={profileName}
                maxLength={120}
                required
                disabled={profileBusy}
                onChange={(event) => setProfileName(event.target.value)}
              />
            </label>
            <label>
              Окружение
              <input
                value={profileEnvironment}
                maxLength={50}
                required
                disabled={profileBusy}
                onChange={(event) => setProfileEnvironment(event.target.value)}
              />
            </label>
            <div className="button-row">
              <button className="button button-primary" disabled={profileBusy}>
                {profileBusy ? "Сохраняем…" : "Сохранить изменения"}
              </button>
              <button
                className="button button-secondary"
                type="button"
                disabled={profileBusy}
                onClick={() => setProfileOpen(false)}
              >
                Отмена
              </button>
            </div>
          </form>
        </Modal>
      )}
      {deleting && (
        <AdminConfirmation
          title="Удалить подключения"
          confirmLabel="Удалить из приложения"
          danger
          onClose={() => setDeleting(false)}
          onConfirm={deleteChosen}
          warning="Будут удалены выбранные подключения и сохранённые в приложении результаты проверок. Объекты в Kubernetes не изменяются и не удаляются."
        >
          <Definition
            items={chosen.map((cluster) => [
              cluster.name,
              cluster.server,
            ])}
          />
        </AdminConfirmation>
      )}
    </>
  );
}
