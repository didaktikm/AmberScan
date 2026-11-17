import { useEffect, useRef, useState, type FormEvent } from "react";
import { FileKey2, Settings2 } from "lucide-react";
import {
  ApiError,
  api,
  errorText,
  MAX_KUBECONFIG_BYTES,
  readTextFile,
} from "./api";
import { useResource } from "./hooks";
import { NamespacePicker } from "./NamespacePicker";
import {
  NamespaceCoverage,
  NamespaceError,
  UnsupportedClusterScope,
  useNamespaceAccess,
} from "./NamespaceAccess";
import { namespaceError, selectedNamespaces } from "./namespaces";
import { canManage, credentialValid, formatDate } from "./utils";
import { Definition, ErrorBox, Modal, Notice, Spinner } from "./ui";
import { SettingsModal } from "./pages/Settings";
import type {
  Capabilities,
  Cluster,
  KubeContext,
  ScopeResult,
  StorageMode,
  User,
} from "./types";

import { AuthorizationChoice, CredentialRecovery } from "./CredentialRecovery";

function DraftConnection({
  initial,
  onClose,
  onCreated,
  onChanged,
  settingsRevision,
  onBusyChanged,
}: {
  initial: Cluster;
  onClose: () => void;
  onCreated: (cluster: Cluster) => void;
  onChanged?: () => void;
  settingsRevision: number;
  onBusyChanged: (value: boolean) => void;
}) {
  const [cluster, setCluster] = useState(initial);
  const access = useNamespaceAccess(cluster);
  const [busy, setBusy] = useState<string>();
  const [recovering, setRecovering] = useState(false);
  const [aborting, setAborting] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const valid =
    cluster.status === "authorized" &&
    credentialValid(cluster.credential_expires_at);
  useEffect(() => {
    if (valid) void access.discover();
  }, [cluster]);
  useEffect(() => {
    // Only the server knows whether Kubernetes policy changed.
    if (settingsRevision > 0) void action("refresh");
  }, [settingsRevision]);
  useEffect(() => {
    onBusyChanged(!!busy || !!access.busy || recovering);
    return () => onBusyChanged(false);
  }, [busy, access.busy, recovering, onBusyChanged]);
  async function action(kind: string) {
    access.invalidate();
    setBusy(kind);
    try {
      if (kind === "refresh") {
        const value = await api<Cluster>(
          `/cluster-drafts/${encodeURIComponent(cluster.id)}`,
        );
        if (alive.current) {
          setCluster(value);
          onChanged?.();
        }
      } else if (kind === "abort") {
        await api(`/cluster-drafts/${encodeURIComponent(cluster.id)}`, {
          method: "DELETE",
        });
        if (alive.current) {
          onChanged?.();
          onClose();
        }
      }
    } catch (reason) {
      if (alive.current) access.setError(namespaceError(reason));
    } finally {
      if (alive.current) setBusy(undefined);
    }
  }
  async function finalize() {
    if (!access.canProceed || !valid) return;
    setBusy("finalize");
    access.setError(undefined);
    try {
      const result = await api<ScopeResult>(
        `/cluster-drafts/${encodeURIComponent(cluster.id)}/finalize`,
        {
          method: "POST",
          body: {
            namespaces: selectedNamespaces(access.selected),
            expected_access_revision: cluster.access_revision,
            accept_partial: access.acceptPartial,
          },
        },
      );
      if (alive.current) onCreated(result.cluster);
    } catch (reason) {
      if (alive.current) {
        access.invalidate();
        access.setError(namespaceError(reason));
      }
    } finally {
      if (alive.current) setBusy(undefined);
    }
  }
  const blocked = !!busy || !!access.busy || recovering;
  return (
    <section className="form-stack">
      <ol className="wizard-steps" aria-label="Этапы завершения подключения">
        {[
          "Учётные данные",
          "Пространства имён",
          "Проверка доступа",
          "Сохранение",
        ].map((step, index) => (
          <li
            className={
              index ===
              (!valid
                ? 0
                : !access.selected.length
                  ? 1
                  : !access.coverage
                    ? 2
                    : 3)
                ? "step-current"
                : ""
            }
            key={step}
          >
            <span>{index + 1}</span>
            {step}
          </li>
        ))}
      </ol>
      <Notice>
        Черновик принадлежит только вам; он ещё не доступен для запусков.
        Закрытие окна не удаляет черновик. Продолжите из списка «Мои черновики»
        до {formatDate(cluster.draft_expires_at)}.
      </Notice>
      <Definition
        items={[
          ["Название", cluster.name],
          ["Окружение", cluster.environment],
          ["Контекст", cluster.context],
          ["Адрес API", cluster.server],
          ["Авторизация", "Kubeconfig"],
        ]}
      />
      <NamespaceError error={access.error} />
      <CredentialRecovery
        cluster={cluster}
        disabled={!!busy || !!access.busy}
        onBusyChanged={setRecovering}
        onUpdated={(value) => {
          access.invalidate(true);
          setCluster(value);
          onChanged?.();
        }}
      />
      <NamespacePicker
        selected={access.selected}
        onChange={access.change}
        options={access.discovery?.items ?? []}
        loaded={!!access.discovery}
        stale={access.discoveryStale}
        complete={access.discovery?.complete ?? false}
        forbidden={access.discovery?.status === "forbidden"}
        limitation={access.discovery?.limitation}
        hint={cluster.namespace_hint}
        onRefresh={() => void access.discover()}
        onLoadMore={
          access.discovery?.continuation && !access.discoveryStale
            ? () => void access.loadMore()
            : undefined
        }
        loading={access.busy === "discovery"}
        disabled={!!busy || !valid}
      />
      <button
        type="button"
        className="button button-secondary"
        disabled={blocked || !valid || !access.selected.length}
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
      <UnsupportedClusterScope />
      <Notice>
        При сохранении сервер ещё раз проверит только выбранную область. Ни
        получение списка, ни его обновление не сохраняют область автоматически.
      </Notice>
      {aborting && (
        <Notice tone="warning">
          Удалить этот черновик вместе с вашей авторизацией? Это действие нельзя
          отменить.
        </Notice>
      )}
      <div className="modal-footer">
        <button
          type="button"
          className="button button-secondary"
          onClick={onClose}
          disabled={blocked}
        >
          Закрыть, продолжить позже
        </button>
        <button
          type="button"
          className="text-button danger-text"
          disabled={blocked}
          onClick={() => (aborting ? void action("abort") : setAborting(true))}
        >
          {aborting ? "Подтвердить удаление черновика" : "Отменить подключение"}
        </button>
        <button
          type="button"
          className="button button-primary"
          disabled={blocked || !valid || !access.canProceed}
          onClick={() => void finalize()}
        >
          {busy === "finalize"
            ? "Повторная проверка доступа и сохранение…"
            : "Сохранить подключение"}
        </button>
      </div>
    </section>
  );
}

export function ClusterWizard({
  capabilities,
  capabilitiesLoading,
  capabilitiesError,
  reloadCapabilities,
  user,
  onClose,
  onCreated,
  resumeId,
  onDraftChanged,
}: {
  capabilities?: Capabilities;
  capabilitiesLoading: boolean;
  capabilitiesError?: string;
  reloadCapabilities: () => void;
  user: User;
  onClose: () => void;
  onCreated: (cluster: Cluster) => void;
  resumeId?: string;
  onDraftChanged?: () => void;
}) {
  const resumed = useResource<Cluster>(
    resumeId ? `/cluster-drafts/${encodeURIComponent(resumeId)}` : null,
  );
  const [draft, setDraft] = useState<Cluster>();
  const [step, setStep] = useState(0);
  const [storage, setStorage] = useState<StorageMode>("run_only");
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState("");
  const [contexts, setContexts] = useState<KubeContext[]>([]);
  const [context, setContext] = useState("");
  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("");
  const [busy, setBusy] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState<string>();
  const [duplicate, setDuplicate] = useState<string>();
  const [aliasName, setAliasName] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsRevision, setSettingsRevision] = useState(0);
  const [draftBusy, setDraftBusy] = useState(false);
  const operation = useRef(0);
  useEffect(
    () => () => {
      operation.current += 1;
    },
    [],
  );
  const connection = draft ?? resumed.data;
  const selectedContext = contexts.find((item) => item.context === context);
  const supportedCredentials = ["token", "client_certificate"].includes(
    selectedContext?.auth_type ?? "",
  );
  function dismiss() {
    operation.current += 1;
    setContent("");
    setContexts([]);
    setFileName("");
    onClose();
  }
  async function chooseFile(file?: File) {
    const attempt = ++operation.current;
    setError(undefined);
    setContent("");
    setFileName("");
    setContexts([]);
    setContext("");
    if (!file) return;
    setReading(true);
    try {
      const text = await readTextFile(file, MAX_KUBECONFIG_BYTES);
      if (attempt !== operation.current) return;
      setContent(text);
      setFileName(file.name);
    } catch (reason) {
      if (attempt === operation.current) setError(errorText(reason));
    } finally {
      if (attempt === operation.current) setReading(false);
    }
  }
  async function next(event: FormEvent) {
    event.preventDefault();
    const attempt = ++operation.current;
    setError(undefined);
    setBusy(true);
    try {
      if (step === 0) {
        const result = await api<{ contexts: KubeContext[] }>(
          "/kubeconfig/inspect",
          { method: "POST", body: { content } },
        );
        if (attempt !== operation.current) return;
        if (!result.contexts.length)
          throw new Error("В файле нет поддерживаемых контекстов.");
        setContexts(result.contexts);
        setStep(1);
      } else if (step === 1) {
        if (!contexts.some((item) => item.context === context))
          throw new Error("Явно выберите контекст.");
        if (!supportedCredentials)
          throw new Error(
            "Неподдерживаемый контекст: нужен самодостаточный kubeconfig со встроенным токеном или клиентским сертификатом и ключом. Механизмы exec, auth-provider и пути к файлам не поддерживаются.",
          );
        setStep(2);
      } else {
        await createDraft(name.trim(), false, attempt);
      }
    } catch (reason) {
      if (attempt !== operation.current) return;
      if (reason instanceof ApiError && reason.code === "cluster_duplicate") {
        setDuplicate(reason.message);
        setAliasName("");
      } else setError(errorText(reason));
    } finally {
      if (attempt === operation.current) setBusy(false);
    }
  }
  async function createDraft(
    draftName: string,
    acceptAlias: boolean,
    attempt = ++operation.current,
  ) {
    if (!draftName || !environment.trim())
      throw new Error("Название и окружение не должны состоять из пробелов.");
    const result = await api<Cluster>("/cluster-drafts", {
      method: "POST",
      body: {
        name: draftName,
        environment: environment.trim(),
        auth_type: "kubeconfig",
        storage_mode: storage,
        accept_alias: acceptAlias,
        connection: { kind: "kubeconfig", content, context },
      },
    });
    if (attempt !== operation.current) return;
    setContent("");
    setContexts([]);
    setFileName("");
    setDuplicate(undefined);
    setDraft(result);
    onDraftChanged?.();
  }
  async function confirmAlias() {
    const attempt = ++operation.current;
    setBusy(true);
    setError(undefined);
    try {
      await createDraft(aliasName.trim(), true, attempt);
    } catch (reason) {
      if (attempt !== operation.current) return;
      if (reason instanceof ApiError && reason.code === "cluster_duplicate")
        setDuplicate(reason.message);
      else setError(errorText(reason));
    } finally {
      if (attempt === operation.current) setBusy(false);
    }
  }
  return (
    <Modal
      wide
      title={resumeId ? "Продолжить подключение" : "Подключение кластера"}
      subtitle="Kubeconfig → выбор пространств имён → проверка доступа → сохранение"
      onClose={dismiss}
      busy={busy || reading || draftBusy}
    >
      <div className="wizard-settings-entry">
        <p className="small muted">
          Настройте исходящие подключения к Kubernetes. Исходный kubeconfig и
          сертификаты остаются только в памяти формы до создания черновика.
        </p>
        {canManage(user.role) && (
          <button
            type="button"
            className="button button-secondary button-small"
            disabled={busy || reading || draftBusy}
            onClick={() => setSettingsOpen(true)}
          >
            <Settings2 size={15} />
            Настройки подключений
          </button>
        )}
      </div>
      {resumeId && !resumed.data && (
        <>
          {resumed.loading && <Spinner label="Загружаем ваш черновик…" />}
          <ErrorBox message={resumed.error} retry={resumed.reload} />
        </>
      )}
      {connection ? (
        <DraftConnection
          key={connection.id}
          initial={connection}
          onClose={dismiss}
          onCreated={onCreated}
          onChanged={onDraftChanged}
          settingsRevision={settingsRevision}
          onBusyChanged={setDraftBusy}
        />
      ) : (
        !resumeId && (
          <form className="form-stack" onSubmit={next}>
            <ol className="wizard-steps" aria-label="Этапы метаданных">
              {["Источник", "Контекст", "Метаданные"].map((title, index) => (
                <li
                  key={title}
                  className={
                    index === step
                      ? "step-current"
                      : index < step
                        ? "step-done"
                        : ""
                  }
                >
                  <span>{index + 1}</span>
                  {title}
                </li>
              ))}
            </ol>
            <ErrorBox message={error} />
            {duplicate && (
              <div className="duplicate-prompt">
                <h3>Этот кластер уже добавлен</h3>
                <p>{duplicate}</p>
                <p>
                  Хотите добавить его ещё раз под другим именем? Адрес API,
                  контекст и сертификат останутся теми же.
                </p>
                <label>
                  Другое имя
                  <input
                    value={aliasName}
                    required
                    maxLength={120}
                    disabled={busy}
                    onChange={(event) => setAliasName(event.target.value)}
                  />
                </label>
                <div className="button-row">
                  <button
                    type="button"
                    className="button button-primary"
                    disabled={busy || !aliasName.trim()}
                    onClick={() => void confirmAlias()}
                  >
                    Добавить под другим именем
                  </button>
                  <button
                    type="button"
                    className="button button-secondary"
                    disabled={busy}
                    onClick={() => setDuplicate(undefined)}
                  >
                    Не добавлять
                  </button>
                </div>
              </div>
            )}
            {step === 0 && (
              <>
                <div className="file-upload">
                  <FileKey2 size={31} />
                  <h3>Выберите kubeconfig</h3>
                  <p>
                    YAML до 256 КиБ, включая config без расширения. Будут
                    использованы метаданные и личные учётные данные выбранного
                    контекста.
                  </p>
                  <input
                    aria-label="Файл kubeconfig"
                    type="file"
                    disabled={busy || reading}
                    onChange={(event) => {
                      void chooseFile(event.target.files?.[0]);
                      event.target.value = "";
                    }}
                  />
                  {fileName && (
                    <span className="selected-file">{fileName}</span>
                  )}
                </div>
                <Notice tone="warning">
                  Поддерживаются встроенный токен или клиентский сертификат и
                  ключ. Исходный YAML не сохраняется на сервере. Механизмы exec
                  и auth-provider никогда не исполняются, пути к файлам не
                  читаются; отключение TLS не поддерживается.
                </Notice>
              </>
            )}
            {step === 1 && (
              <>
                <h3>Какой контекст использовать?</h3>
                <p className="small muted">
                  Текущий контекст не выбирается автоматически. Смена контекста
                  не переносит область доступа.
                </p>
                <div className="context-list">
                  {contexts.map((item) => (
                    <label
                      key={item.context}
                      className={`context-option ${context === item.context ? "context-selected" : ""}`}
                    >
                      <input
                        type="radio"
                        name="context"
                        required
                        checked={context === item.context}
                        onChange={() => {
                          setContext(item.context);
                          setError(undefined);
                        }}
                      />
                      <div>
                        <strong>{item.context}</strong>
                        <span>{item.cluster_name}</span>
                        <code>{item.server}</code>
                        {item.namespace_hint && (
                          <small>
                            Подсказка пространства имён: {item.namespace_hint}{" "}
                            (не выбрано)
                          </small>
                        )}
                        {item.warnings.map((warning, index) => (
                          <span className="context-warning" key={index}>
                            {warning}
                          </span>
                        ))}
                      </div>
                    </label>
                  ))}
                </div>
              </>
            )}
            {step === 2 && (
              <>
                <div className="form-columns">
                  <label>
                    Название кластера
                    <input
                      required
                      maxLength={120}
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                    />
                  </label>
                  <label>
                    Окружение
                    <input
                      required
                      maxLength={50}
                      value={environment}
                      onChange={(event) => setEnvironment(event.target.value)}
                    />
                  </label>
                </div>
                <Notice>
                  Личные учётные данные:{" "}
                  {selectedContext?.auth_type === "token"
                    ? "встроенный токен"
                    : "клиентский сертификат и ключ"}
                  .
                </Notice>
                <AuthorizationChoice value={storage} onChange={setStorage} />
                {capabilitiesLoading && (
                  <Spinner label="Проверяем настройки подключений…" />
                )}
                <ErrorBox
                  message={capabilitiesError}
                  retry={reloadCapabilities}
                />
                {capabilities?.kubernetes_setup_required && (
                  <Notice tone="warning">
                    Не настроены правила сети для Kubernetes. Настройте
                    исходящие подключения к Kubernetes выше.
                  </Notice>
                )}
                <Definition
                  items={[
                    ["Контекст", context],
                    ["Адрес API", selectedContext?.server],
                  ]}
                />
                <Notice>
                  Создаётся только ваш временный черновик. Пространства имён
                  будут выбраны после личной авторизации; готовое подключение
                  пока не создаётся.
                </Notice>
              </>
            )}
            <div className="modal-footer">
              <button
                type="button"
                className="button button-secondary"
                disabled={busy || reading}
                onClick={() => {
                  if (step === 0) dismiss();
                  else {
                    setStep(step - 1);
                    setError(undefined);
                  }
                }}
              >
                {step ? "Назад" : "Отмена"}
              </button>
              <button
                type="submit"
                className="button button-primary"
                disabled={
                  busy ||
                  reading ||
                  (step === 0 && !content) ||
                  (step === 1 && !context)
                }
              >
                {busy
                  ? "Обработка…"
                  : step === 2
                    ? "Создать черновик"
                    : step === 0
                      ? "Проверить файл"
                      : "Продолжить"}
              </button>
            </div>
          </form>
        )
      )}
      {settingsOpen && (
        <SettingsModal
          user={user}
          onSaved={() => {
            setSettingsRevision((value) => value + 1);
            reloadCapabilities();
          }}
          onClose={() => {
            setSettingsOpen(false);
            reloadCapabilities();
          }}
        />
      )}
    </Modal>
  );
}
