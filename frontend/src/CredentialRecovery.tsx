import { useEffect, useRef, useState } from "react";
import { api, errorText, MAX_KUBECONFIG_BYTES, readTextFile } from "./api";
import { clusterAccessKey } from "./namespaces";
import { Definition, ErrorBox, Modal, Notice } from "./ui";
import type { Cluster, StorageMode } from "./types";

export function AuthorizationChoice({
  value,
  onChange,
  disabled,
}: {
  value: StorageMode;
  onChange: (mode: StorageMode) => void;
  disabled?: boolean;
}) {
  return (
    <fieldset
      className="settings-fieldset authorization-choice"
      disabled={disabled}
    >
      <legend>Как использовать новую авторизацию</legend>
      <label className="checkbox-label">
        <input
          type="radio"
          name="authorization-storage"
          checked={value === "run_only"}
          onChange={() => onChange("run_only")}
          value="run_only"
        />
        <span>
          <strong>На один запуск (по умолчанию)</strong>
          <small>
            Только в текущей локальной сессии, не дольше 1 часа. Получение
            списка и проверка доступа не расходуют авторизацию; постановка
            проверки в очередь расходует её один раз. Неиспользованный доступ
            удаляется при выходе.
          </small>
        </span>
      </label>
      <label className="checkbox-label">
        <input
          type="radio"
          name="authorization-storage"
          checked={value === "persistent"}
          onChange={() => onChange("persistent")}
          value="persistent"
        />
        <span>
          <strong>Сохранить на сервере — до 24 часов</strong>
          <small>
            Явное согласие на личное зашифрованное хранение для повторных
            проверок до истечения срока или отзыва. Остаётся после выхода из
            AmberData. Учётные данные не сохраняются в браузере.
          </small>
        </span>
      </label>
      <p className="small muted">
        Это срок личного доступа в приложении, не подтверждённый срок действия
        токена Kubernetes. Срок сертификата или исходных учётных данных может
        его сократить. Автоматического обновления нет.
      </p>
    </fieldset>
  );
}

/** A replacement is usable only while the source object and access snapshot remain current. */
export function useRecoveredCluster(source?: Cluster) {
  const [replacement, setReplacement] = useState<{
    source?: Cluster;
    value: Cluster;
  }>();
  return [
    replacement && replacement.source === source ? replacement.value : source,
    (value: Cluster) => setReplacement({ source, value }),
  ] as const;
}

export function CredentialRecovery({
  cluster,
  onUpdated,
  disabled,
  onBusyChanged,
}: {
  cluster: Cluster;
  onUpdated: (cluster: Cluster) => void;
  disabled?: boolean;
  onBusyChanged?: (busy: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState("");
  const [storage, setStorage] = useState<StorageMode>("run_only");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const generation = useRef(0);
  const key = clusterAccessKey(cluster);
  const currentKey = useRef(key);
  currentKey.current = key;
  useEffect(() => {
    generation.current += 1;
    setOpen(false);
    setContent("");
    setFileName("");
    setBusy(false);
    return () => {
      generation.current += 1;
    };
  }, [key]);
  useEffect(() => {
    onBusyChanged?.(busy);
    return () => onBusyChanged?.(false);
  }, [busy, onBusyChanged]);
  function close() {
    generation.current += 1;
    setContent("");
    setFileName("");
    setError(undefined);
    setOpen(false);
  }
  async function choose(file?: File) {
    const attempt = ++generation.current;
    setContent("");
    setFileName("");
    setError(undefined);
    if (!file) return;
    setBusy(true);
    try {
      const text = await readTextFile(file, MAX_KUBECONFIG_BYTES);
      if (attempt === generation.current) {
        setContent(text);
        setFileName(file.name);
      }
    } catch (reason) {
      if (attempt === generation.current) setError(errorText(reason));
    } finally {
      if (attempt === generation.current) setBusy(false);
    }
  }
  async function submit() {
    const attempt = ++generation.current;
    setBusy(true);
    setError(undefined);
    try {
      const updated = await api<Cluster>(
        `/clusters/${encodeURIComponent(cluster.id)}/credential`,
        {
          method: "POST",
          body: {
            content,
            context: cluster.context,
            storage_mode: storage,
            expected_access_revision: cluster.access_revision,
          },
        },
      );
      if (attempt === generation.current && currentKey.current === key) {
        close();
        onUpdated(updated);
      }
    } catch (reason) {
      if (attempt === generation.current) setError(errorText(reason));
    } finally {
      if (currentKey.current === key) setBusy(false);
    }
  }
  return (
    <>
      <button
        type="button"
        className="button button-secondary"
        disabled={disabled || busy}
        onClick={() => {
          setStorage("run_only");
          setOpen(true);
        }}
      >
        Повторно импортировать kubeconfig
      </button>
      {open && (
        <Modal
          title="Повторный импорт личных учётных данных"
          onClose={close}
          busy={busy}
        >
          <div className="form-stack">
            <ErrorBox message={error} />
            <Notice>
              Импорт заменяет только вашу личную авторизацию и отменяет
              устаревшие личные задания. Адрес API, центр сертификации (CA),
              контекст и разрешённые пространства имён не изменяются. Нужен тот
              же контекст со встроенным токеном или клиентским сертификатом и
              ключом; механизм exec и пути к файлам не поддерживаются.
            </Notice>
            <Definition
              items={[
                ["Контекст", cluster.context],
                ["Адрес API", cluster.server],
              ]}
            />
            <label>
              Файл kubeconfig
              <input
                type="file"
                aria-label="Повторный файл kubeconfig"
                disabled={busy}
                onChange={(event) => {
                  void choose(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
            </label>
            {fileName && <p className="small">{fileName}</p>}
            <AuthorizationChoice
              value={storage}
              onChange={setStorage}
              disabled={busy}
            />
            <div className="modal-footer">
              <button
                type="button"
                className="button button-secondary"
                onClick={close}
                disabled={busy}
              >
                Отмена импорта
              </button>
              <button
                type="button"
                className="button button-primary"
                disabled={busy || !content}
                onClick={() => void submit()}
              >
                {busy ? "Передача…" : "Заменить личные учётные данные"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}
