import { useState, type FormEvent } from "react";
import { ArrowRight, Check, FileInput, FileJson, Upload } from "lucide-react";
import { api, errorText, parseReportJson, readTextFile } from "../api";
import { useResource } from "../hooks";
import { ErrorBox, Notice, PageHeader, Panel, Spinner } from "../ui";
import { canScan } from "../utils";
import type { Cluster, Run, User } from "../types";

export function ImportsPage({
  user,
  openRun,
}: {
  user: User;
  openRun: (id: string) => void;
}) {
  const clusters = useResource<Cluster[]>("/clusters");
  const [clusterId, setClusterId] = useState("");
  const [scanner, setScanner] = useState("");
  const [report, setReport] = useState<Record<string, unknown>>();
  const [fileName, setFileName] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [reading, setReading] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [created, setCreated] = useState<Run>();
  async function chooseFile(file?: File) {
    setError(undefined);
    setReport(undefined);
    setFileName("");
    setCreated(undefined);
    if (!file) return;
    setReading(true);
    try {
      const text = await readTextFile(file);
      setReport(parseReportJson(text));
      setFileName(file.name);
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setReading(false);
    }
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    setBusy(true);
    setCreated(undefined);
    try {
      if (!report) throw new Error("Выберите корректный JSON-отчёт.");
      const run = await api<Run>("/imports", {
        method: "POST",
        body: { cluster_id: clusterId, scanner, report },
      });
      setCreated(run);
      setReport(undefined);
      setAcknowledged(false);
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title="Импорт отчётов"
        description="Добавьте результаты внешнего сканера для единого разбора находок и доказательств."
      />
      <div className="import-layout">
        <Panel title="Загрузить JSON-отчёт">
          <div className="panel-body">
            <ErrorBox message={clusters.error} retry={clusters.reload} />
            {!canScan(user.role) ? (
              <Notice>
                Импорт недоступен наблюдателю. Обратитесь к аудитору,
                руководителю ИБ или администратору.
              </Notice>
            ) : clusters.loading && !clusters.data ? (
              <Spinner />
            ) : (
              <form onSubmit={submit} className="form-stack">
                <ErrorBox message={error} />
                {created && (
                  <Notice tone="success">
                    <strong>Отчёт принят сервером.</strong>
                    <p>
                      Создан запуск #{created.id.slice(0, 8)}. Проверяйте
                      реальные находки, покрытие и ограничения в деталях.
                    </p>
                    <button
                      type="button"
                      className="text-button"
                      onClick={() => openRun(created.id)}
                    >
                      Открыть импортированный запуск
                      <ArrowRight size={15} />
                    </button>
                  </Notice>
                )}
                <label>
                  Связать с кластером
                  <select
                    required
                    value={clusterId}
                    onChange={(event) => setClusterId(event.target.value)}
                  >
                    <option value="">Выберите кластер</option>
                    {clusters.data?.map((cluster) => (
                      <option key={cluster.id} value={cluster.id}>
                        {cluster.name} · {cluster.environment}
                      </option>
                    ))}
                  </select>
                  <small>
                    Это ручная привязка отчёта, не подтверждение его
                    происхождения.
                  </small>
                </label>
                {clusters.data?.length === 0 && (
                  <Notice tone="warning">
                    Нет доступных кластеров. Для импорта администратор должен
                    создать подключение и предоставить доступ.
                  </Notice>
                )}
                <label>
                  Источник отчёта
                  <select
                    required
                    value={scanner}
                    onChange={(event) => setScanner(event.target.value)}
                  >
                    <option value="">Выберите формат сканера</option>
                    <option value="trivy">Trivy — JSON-отчёт образа</option>
                    <option value="kube-bench">kube-bench — JSON</option>
                    <option value="kubescape">Kubescape — JSON</option>
                  </select>
                </label>
                <div className="file-upload file-upload-small">
                  <FileJson size={29} />
                  <h3>Исходный файл сканера</h3>
                  <p>
                    Только JSON-объект, до 900 КБ. Поддержка схемы проверяется
                    сервером.
                  </p>
                  <input
                    key={created?.id ?? "report"}
                    type="file"
                    accept=".json,application/json"
                    disabled={reading || busy}
                    aria-label="Выберите JSON-отчёт сканера"
                    onChange={(event) =>
                      void chooseFile(event.target.files?.[0])
                    }
                  />
                  {report && (
                    <span className="selected-file">
                      <Check size={14} />
                      {fileName} · JSON прочитан
                    </span>
                  )}
                </div>
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    required
                    checked={acknowledged}
                    onChange={(event) => setAcknowledged(event.target.checked)}
                  />
                  <span>
                    Я проверил выбранный кластер и понимаю, что импорт не
                    подтверждает источник данных. Отчёт не содержит секретов.
                  </span>
                </label>
                <button
                  className="button button-primary"
                  type="submit"
                  disabled={
                    busy || !report || !clusterId || !scanner || !acknowledged
                  }
                >
                  <Upload size={16} />
                  {busy ? "Импорт и нормализация…" : "Импортировать отчёт"}
                </button>
              </form>
            )}
          </div>
        </Panel>
        <aside className="import-explainer">
          <div className="mode-icon">
            <FileInput size={27} />
          </div>
          <h2>
            Внешние данные.
            <br />
            Явные ограничения.
          </h2>
          <p>
            Импорт — не проверка работающего кластера. Он сохраняет наблюдения
            из файла, который вы загрузили.
          </p>
          <div className="import-rule">
            <strong>Схема проверяется</strong>
            <p>
              Неизвестный или повреждённый формат вызывает ошибку, а не
              «успешный» пустой результат.
            </p>
          </div>
          <div className="import-rule">
            <strong>Происхождение отмечается</strong>
            <p>
              В отчёте сохраняются источник, версии, покрытие и ограничения,
              предоставленные API.
            </p>
          </div>
          <div className="import-rule">
            <strong>Секреты не нужны</strong>
            <p>
              Не загружайте учётные данные, переменные окружения или дампы
              ресурсов с конфиденциальными значениями.
            </p>
          </div>
          <Notice>
            Сканеры командной строки Trivy, kube-bench и Kubescape не
            запускаются из этой формы.
          </Notice>
        </aside>
      </div>
    </>
  );
}
