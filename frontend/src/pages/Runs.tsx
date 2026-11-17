import { useState } from "react";
import {
  ArrowLeft,
  Clock3,
  Download,
  Play,
  RefreshCw,
  ScanLine,
  Square,
  X,
} from "lucide-react";
import { api, downloadReport, errorText } from "../api";
import { useClock, useResource } from "../hooks";
import {
  Badge,
  CoverageTable,
  Definition,
  EmptyState,
  ErrorBox,
  Notice,
  PageHeader,
  Pagination,
  Panel,
  Spinner,
} from "../ui";
import {
  canScan,
  elapsed,
  formatDate,
  isActive,
  pretty,
  shortId,
  stageLabels,
  statusLabels,
} from "../utils";
import { RunLaunch } from "../RunLaunch";
import { FindingDialog, FindingTable } from "./Findings";
import type { Cluster, Finding, Run, User } from "../types";

function RunDetail({
  id,
  user,
  onBack,
}: {
  id: string;
  user: User;
  onBack: () => void;
}) {
  const resource = useResource<Run>(`/runs/${encodeURIComponent(id)}`, 5_000);
  const run = resource.data;
  const findings = run?.findings?.map((finding) => ({
    ...finding,
    cluster_name: finding.cluster_name || run.cluster_name,
  }));
  const now = useClock(run ? isActive(run) : false);
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [cancelConfirm, setCancelConfirm] = useState(false);
  const [selected, setSelected] = useState<Finding>();
  const [format, setFormat] = useState<"json" | "markdown" | "html">("json");
  async function cancel() {
    setBusy("cancel");
    setError(undefined);
    try {
      const updated = await api<Run>(`/runs/${encodeURIComponent(id)}/cancel`, {
        method: "POST",
      });
      resource.setData(updated);
      resource.reload();
      setCancelConfirm(false);
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(undefined);
    }
  }
  async function download() {
    setBusy("download");
    setError(undefined);
    try {
      await downloadReport(id, format);
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(undefined);
    }
  }
  return (
    <>
      <button className="text-button back-button" onClick={onBack}>
        <ArrowLeft size={15} />
        Все проверки
      </button>
      <PageHeader
        title={`Проверка #${shortId(id)}`}
        description={
          run
            ? `${run.cluster_name} · Создана ${formatDate(run.created_at)}`
            : "Получение данных запуска"
        }
        action={
          <button className="button button-secondary" onClick={resource.reload}>
            <RefreshCw size={16} />
            Обновить
          </button>
        }
      />
      <ErrorBox message={resource.error} retry={resource.reload} />
      <ErrorBox message={error} />
      {resource.loading && !run ? (
        <Spinner />
      ) : (
        run && (
          <>
            <div className="run-status-strip">
              <div>
                <Badge value={run.status} />
                <span className="run-stage">
                  {stageLabels[run.stage] ?? run.stage ?? "Этап не сообщён"}
                </span>
              </div>
              <span className="elapsed">
                <Clock3 size={16} />
                {elapsed(run, now)}
              </span>
            </div>
            {isActive(run) && (
              <Notice>
                {run.status === "queued"
                  ? "Запуск находится в очереди. Проверка ещё не началась."
                  : "Проверка выполняется. Данные обновляются каждые 5 секунд."}{" "}
                Процент выполнения не рассчитывается: сервер сообщает только
                фактический этап и покрытие.
              </Notice>
            )}
            {run.cancel_requested && (
              <Notice tone="warning">
                Запрошена отмена. Она не считается выполненной, пока обработчик
                не сообщит итоговое состояние.
              </Notice>
            )}
            {run.error && (
              <div className="notice notice-error" role="alert">
                <X size={18} />
                <div>
                  <strong>Ошибка проверки</strong>
                  <p>{run.error}</p>
                </div>
              </div>
            )}
            <Panel title="Сведения о запуске">
              <div className="panel-body">
                <Definition
                  items={[
                    ["ID", run.id],
                    ["Кластер", run.cluster_name],
                    ["Создан", formatDate(run.created_at)],
                    ["Начат", formatDate(run.started_at)],
                    ["Завершён", formatDate(run.finished_at)],
                    ["Длительность выполнения", elapsed(run, now)],
                    ["Источник", run.source ?? run.scanner ?? "Не сообщён"],
                    [
                      "Область",
                      run.namespaces?.join(", ") ||
                        (run.scope
                          ? pretty(run.scope)
                          : "Не передана в деталях; проверьте отчёт"),
                    ],
                  ]}
                />
              </div>
            </Panel>
            {canScan(user.role) && (
              <div className="run-actions">
                <div className="export-controls">
                  <label className="sr-only" htmlFor="report-format">
                    Формат отчёта
                  </label>
                  <select
                    id="report-format"
                    value={format}
                    onChange={(event) =>
                      setFormat(event.target.value as typeof format)
                    }
                  >
                    <option value="json">JSON</option>
                    <option value="markdown">Markdown</option>
                    <option value="html">HTML</option>
                  </select>
                  <button
                    className="button button-secondary"
                    disabled={!!busy}
                    onClick={() => void download()}
                  >
                    <Download size={16} />
                    {busy === "download" ? "Загрузка…" : "Скачать отчёт"}
                  </button>
                </div>
                {isActive(run) &&
                  !run.cancel_requested &&
                  (cancelConfirm ? (
                    <div className="button-row">
                      <span className="small">Отменить запуск?</span>
                      <button
                        className="button button-danger"
                        disabled={!!busy}
                        onClick={() => void cancel()}
                      >
                        {busy === "cancel" ? "Запрос…" : "Да, отменить"}
                      </button>
                      <button
                        className="button button-secondary"
                        onClick={() => setCancelConfirm(false)}
                      >
                        Продолжить проверку
                      </button>
                    </div>
                  ) : (
                    <button
                      className="button button-secondary danger-text"
                      onClick={() => setCancelConfirm(true)}
                    >
                      <Square size={14} />
                      Отменить запуск
                    </button>
                  ))}
              </div>
            )}
            <Panel
              title="Покрытие проверок"
              action={
                <span className="small muted">
                  Результат каждого доступного шага
                </span>
              }
            >
              <CoverageTable coverage={run.coverage} />
            </Panel>
            <Panel
              title="Находки этого запуска"
              action={
                <span className="small muted">
                  {run.findings ? run.findings.length : "Не переданы"}
                </span>
              }
            >
              {findings?.length ? (
                <FindingTable findings={findings} onSelect={setSelected} />
              ) : (
                <EmptyState
                  icon={<ScanLine size={29} />}
                  title={run.findings ? "Находок нет" : "Находки не переданы"}
                >
                  {isActive(run)
                    ? "Результаты могут появиться после завершения. До этого момента вывод о безопасности делать нельзя."
                    : "Сопоставьте этот результат с покрытием и ограничениями. Непроверенная область не считается безопасной."}
                </EmptyState>
              )}
            </Panel>
            <div className="detail-columns">
              <Panel title="Ограничения">
                <div className="panel-body">
                  {run.limitations?.length ? (
                    <ul className="limitations">
                      {run.limitations.map((limitation, index) => (
                        <li key={index}>{limitation}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="muted small">
                      Сервер не указал ограничений. Это не подтверждает полное
                      покрытие Kubernetes.
                    </p>
                  )}
                </div>
              </Panel>
              <Panel title="Версии и происхождение">
                <div className="panel-body">
                  <pre>{pretty(run.versions ?? {})}</pre>
                  <p className="small muted">
                    Импортированные отчёты не подтверждают происхождение данных
                    из выбранного кластера.
                  </p>
                </div>
              </Panel>
            </div>
          </>
        )
      )}
      {selected && (
        <FindingDialog
          finding={selected}
          user={user}
          onClose={() => setSelected(undefined)}
          onChanged={resource.reload}
        />
      )}
    </>
  );
}

export function RunsPage({
  user,
  selectedRun,
  setSelectedRun,
}: {
  user: User;
  selectedRun?: string;
  setSelectedRun: (id?: string) => void;
}) {
  const [offset, setOffset] = useState(0);
  const runs = useResource<Run[]>(`/runs?offset=${offset}`, 10_000);
  const clusters = useResource<Cluster[]>("/clusters");
  const [launch, setLaunch] = useState(false);
  const [status, setStatus] = useState("");
  const [clusterId, setClusterId] = useState("");
  const now = useClock(!!runs.data?.some(isActive));
  const shown = runs.data?.filter(
    (run) =>
      (!status || run.status === status) &&
      (!clusterId || run.cluster_id === clusterId),
  );
  if (selectedRun)
    return (
      <RunDetail
        key={selectedRun}
        id={selectedRun}
        user={user}
        onBack={() => {
          setSelectedRun(undefined);
          runs.reload();
        }}
      />
    );
  return (
    <>
      <PageHeader
        title="Проверки"
        description="Очередь, фактические этапы и результаты запусков. Без расчётных процентов выполнения."
        action={
          <div className="button-row">
            <button
              className="button button-secondary"
              onClick={() => {
                runs.reload();
                clusters.reload();
              }}
            >
              <RefreshCw size={16} />
              Обновить
            </button>
            {canScan(user.role) && (
              <button
                className="button button-primary"
                disabled={!clusters.data?.length}
                onClick={() => setLaunch(true)}
              >
                <Play size={16} />
                Запустить проверку
              </button>
            )}
          </div>
        }
      />
      <div className="filter-bar compact-filters">
        <label>
          Кластер
          <select
            value={clusterId}
            onChange={(event) => setClusterId(event.target.value)}
          >
            <option value="">Все доступные</option>
            {clusters.data?.map((cluster) => (
              <option key={cluster.id} value={cluster.id}>
                {cluster.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Состояние
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="">Любое</option>
            {[
              "queued",
              "running",
              "completed",
              "partial",
              "failed",
              "cancelled",
              "interrupted",
            ].map((value) => (
              <option key={value} value={value}>
                {statusLabels[value]}
              </option>
            ))}
          </select>
        </label>
        <span className="filter-note">
          Фильтры на текущей странице · Обновление каждые 10 с
        </span>
      </div>
      <ErrorBox message={runs.error} retry={runs.reload} />
      <ErrorBox message={clusters.error} retry={clusters.reload} />
      {canScan(user.role) && clusters.data?.length === 0 && (
        <Notice>
          Для запуска нужен доступный кластер с вашей действующей личной
          авторизацией из kubeconfig. Создание подключения доступно
          администратору.
        </Notice>
      )}
      <Panel
        title="История запусков"
        action={
          <span className="small muted">{shown?.length ?? "—"} записей</span>
        }
      >
        {runs.loading && !runs.data ? (
          <Spinner />
        ) : shown?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Запуск</th>
                  <th>Кластер</th>
                  <th>Состояние / этап</th>
                  <th>Создан</th>
                  <th>Длительность</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <button
                        className="table-link"
                        onClick={() => setSelectedRun(run.id)}
                      >
                        #{shortId(run.id)}
                        <span>Открыть результаты</span>
                      </button>
                    </td>
                    <td>{run.cluster_name}</td>
                    <td>
                      <Badge value={run.status} />
                      <span className="cell-subtext">
                        {stageLabels[run.stage] ?? run.stage ?? "—"}
                        {run.cancel_requested ? " · Отмена запрошена" : ""}
                      </span>
                    </td>
                    <td className="nowrap cell-secondary">
                      {formatDate(run.created_at)}
                    </td>
                    <td className="nowrap cell-secondary">
                      {elapsed(run, now)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          shown && (
            <EmptyState
              icon={<ScanLine size={32} />}
              title={
                status || clusterId
                  ? "Запусков по фильтру нет"
                  : "Проверок пока нет"
              }
            >
              {status || clusterId
                ? "Выберите другой кластер или состояние."
                : "Запустите встроенную проверку доступного кластера или импортируйте отчёт. Здесь появятся только реальные запуски API."}
            </EmptyState>
          )
        )}
      </Panel>
      <Pagination
        offset={offset}
        count={runs.data?.length}
        loading={runs.loading}
        onChange={setOffset}
      />
      {launch && (
        <RunLaunch
          clusters={clusters.data ?? []}
          onClose={() => setLaunch(false)}
          onCreated={(run) => {
            setLaunch(false);
            runs.reload();
            setSelectedRun(run.id);
          }}
        />
      )}
    </>
  );
}
