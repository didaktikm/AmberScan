import { useState } from "react";
import {
  LockKeyhole,
  Activity,
  ArrowRight,
  Boxes,
  FileInput,
  Fingerprint,
  Plus,
  RefreshCw,
  ScanLine,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { useResource } from "../hooks";
import {
  Badge,
  Definition,
  EmptyState,
  ErrorBox,
  Notice,
  PageHeader,
  Pagination,
  Panel,
  Spinner,
} from "../ui";
import { canManage, canScan, formatDate, pretty, shortId } from "../utils";
import type {
  AuditEvent,
  Capabilities,
  Overview,
  Page,
  Run,
  User,
} from "../types";

export function OverviewPage({
  user,
  navigate,
  openRun,
}: {
  user: User;
  navigate: (page: Page) => void;
  openRun: (id: string) => void;
}) {
  const overview = useResource<Overview>("/overview", 20_000);
  const runs = useResource<Run[]>("/runs", 20_000);
  const capabilities = useResource<Capabilities>("/capabilities");
  const stats = overview.data
    ? [
        {
          label: "Кластеры",
          value: overview.data.clusters,
          note: "В вашей области доступа",
          page: "clusters" as Page,
          icon: Boxes,
        },
        {
          label: "Проверки",
          value: overview.data.runs,
          note: "Все сохранённые запуски",
          page: "runs" as Page,
          icon: ScanLine,
        },
        {
          label: "Находки",
          value: overview.data.findings,
          note: "Нормализованные наблюдения",
          page: "findings" as Page,
          icon: ShieldCheck,
        },
        {
          label: "Пробелы покрытия",
          value: overview.data.coverage_gaps,
          note: "Не равны отсутствию рисков",
          page: "runs" as Page,
          icon: ShieldOff,
        },
      ]
    : [];
  return (
    <>
      <PageHeader
        title="Обзор безопасности"
        description="Состояние проверок и границы того, что действительно удалось проверить."
        action={
          <button
            className="button button-secondary"
            onClick={() => {
              overview.reload();
              runs.reload();
              capabilities.reload();
            }}
          >
            <RefreshCw size={16} />
            Обновить
          </button>
        }
      />
      <ErrorBox message={overview.error} retry={overview.reload} />
      {overview.loading && !overview.data ? (
        <Spinner />
      ) : (
        overview.data && (
          <div className="stats-grid" aria-label="Сводные показатели">
            {stats.map(({ label, value, note, page, icon: Icon }) => (
              <button
                key={label}
                className="stat-tile"
                onClick={() => navigate(page)}
              >
                <div className="stat-heading">
                  <span>{label}</span>
                  <Icon size={18} aria-hidden="true" />
                </div>
                <strong className="stat-number">
                  {new Intl.NumberFormat("ru-RU").format(value)}
                </strong>
                <span className="stat-note">
                  {note}
                  <ArrowRight size={14} />
                </span>
              </button>
            ))}
          </div>
        )
      )}
      {overview.data?.clusters === 0 && (
        <section className="onboarding-panel">
          <div className="onboarding-art" aria-hidden="true">
            <Boxes size={43} strokeWidth={1.2} />
          </div>
          <div>
            <span className="section-kicker">Начните с области проверки</span>
            <h2>Подключите первый кластер</h2>
            <p>
              Импортируйте kubeconfig со встроенным токеном или клиентским
              сертификатом и ключом, явно выберите контекст и пространства имён.
            </p>
            <div className="button-row">
              {canManage(user.role) ? (
                <button
                  className="button button-primary"
                  onClick={() => navigate("clusters")}
                >
                  <Plus size={17} />
                  Подключить кластер
                </button>
              ) : (
                <span className="muted">
                  Для подключения обратитесь к администратору.
                </span>
              )}
              <button
                className="button button-secondary"
                onClick={() => navigate("modes")}
              >
                Границы возможностей
                <ArrowRight size={15} />
              </button>
            </div>
          </div>
        </section>
      )}
      <div className="overview-columns">
        <Panel
          title="Последние проверки"
          action={
            <button className="text-button" onClick={() => navigate("runs")}>
              Все проверки
              <ArrowRight size={14} />
            </button>
          }
        >
          <ErrorBox message={runs.error} retry={runs.reload} />
          {runs.loading && !runs.data ? (
            <Spinner />
          ) : runs.data?.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Кластер / запуск</th>
                    <th>Состояние</th>
                    <th>Создан</th>
                  </tr>
                </thead>
                <tbody>
                  {[...runs.data]
                    .sort(
                      (a, b) =>
                        Date.parse(b.created_at) - Date.parse(a.created_at),
                    )
                    .slice(0, 5)
                    .map((run) => (
                      <tr key={run.id}>
                        <td>
                          <button
                            className="table-link"
                            onClick={() => openRun(run.id)}
                          >
                            {run.cluster_name || "Кластер"}
                            <span>#{shortId(run.id)}</span>
                          </button>
                        </td>
                        <td>
                          <Badge value={run.status} />
                        </td>
                        <td className="cell-secondary nowrap">
                          {formatDate(run.created_at)}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          ) : (
            runs.data && (
              <EmptyState
                icon={<ScanLine size={29} />}
                title="Проверок пока нет"
              >
                После запуска здесь появятся реальные состояния, время и
                доступное покрытие. Счётчики не заполняются примерами.
              </EmptyState>
            )
          )}
        </Panel>
        <Panel title="Важно для интерпретации" className="interpretation-panel">
          <div className="interpretation-item">
            <ShieldOff size={20} />
            <div>
              <h3>Нет находок ≠ безопасно</h3>
              <p>
                Недоступные ресурсы и неподдерживаемые проверки отражаются
                отдельно в покрытии.
              </p>
            </div>
          </div>
          <div className="interpretation-item">
            <FileInput size={20} />
            <div>
              <h3>Импорт не подтверждает источник</h3>
              <p>
                JSON-отчёт связан с выбранным кластером со слов загрузившего
                пользователя.
              </p>
            </div>
          </div>
          <div className="interpretation-item">
            <LockKeyhole size={20} />
            <div>
              <h3>Минимальная область доступа</h3>
              <p>
                Только явно заданные пространства имён. Без чтения Secrets,
                логов и выполнения команд.
              </p>
            </div>
          </div>
        </Panel>
      </div>
      <Panel
        title="Обработчики проверок"
        action={<span className="small muted">Данные API, без симуляции</span>}
      >
        {overview.data?.workers.length ? (
          <div className="worker-list">
            {overview.data.workers.map((worker, index) => (
              <details key={String(worker.id ?? index)}>
                <summary>
                  <Activity size={16} />
                  <strong>
                    {String(
                      worker.name ?? worker.id ?? `Обработчик ${index + 1}`,
                    )}
                  </strong>
                  {typeof worker.status === "string" && (
                    <Badge value={worker.status} />
                  )}
                </summary>
                <pre>{pretty(worker)}</pre>
              </details>
            ))}
          </div>
        ) : overview.data ? (
          <div className="panel-body">
            <Notice tone="warning">
              Сервер не сообщил об активных обработчиках. Наличие запущенного
              API не подтверждает готовность выполнять проверки.
            </Notice>
          </div>
        ) : (
          <div className="panel-body muted">
            Состояние обработчиков пока неизвестно.
          </div>
        )}
      </Panel>
      <div className="overview-bottom">
        <span className="muted">
          {capabilities.data
            ? `Версия ${capabilities.data.version}`
            : "Версия API не получена"}{" "}
          · Данные ограничены правами вашей учётной записи
        </span>
        {canScan(user.role) && (
          <button className="text-button" onClick={() => navigate("imports")}>
            <FileInput size={15} />
            Импортировать готовый отчёт
          </button>
        )}
      </div>
      <ErrorBox message={capabilities.error} retry={capabilities.reload} />
    </>
  );
}

const futureModes = [
  {
    title: "Непрерывное наблюдение",
    detail:
      "Фоновое наблюдение за изменениями, расписания и автоматическое повторное сканирование не реализованы.",
  },
  {
    title: "Исправление ресурсов",
    detail:
      "Автоматическое исправление, применение манифестов и команды в контейнерах не реализованы. Консоль не изменяет кластер.",
  },
  {
    title: "Запуск внешних сканеров",
    detail:
      "Запуск Trivy, kube-bench и Kubescape в кластере не реализован до проверки закреплённых версий и безопасного окружения. Доступен импорт поддерживаемых JSON-схем.",
  },
];
export function ModesPage() {
  const resource = useResource<Capabilities>("/capabilities");
  return (
    <>
      <PageHeader
        title="Возможности и ограничения"
        description="Доступность функций определяется сервером. Будущие режимы не выдают результаты проверок."
      />
      <ErrorBox message={resource.error} retry={resource.reload} />
      {resource.loading && !resource.data ? (
        <Spinner />
      ) : (
        resource.data && (
          <>
            <div className="section-heading">
              <h2>Состояние функций в версии {resource.data.version}</h2>
              <span className="muted">Ответ /api/capabilities</span>
            </div>
            {resource.data.features.length ? (
              <div className="mode-grid">
                {resource.data.features.map((feature) => (
                  <article key={feature.id} className="mode-card">
                    <div className="mode-icon">
                      <ScanLine size={23} />
                    </div>
                    <Badge value={feature.status} />
                    <h3>{feature.title}</h3>
                    <p>{feature.detail}</p>
                    <code>{feature.id}</code>
                  </article>
                ))}
              </div>
            ) : (
              <Notice>
                Сервер не опубликовал список возможностей. Доступность проверок
                не подтверждена.
              </Notice>
            )}
            <Panel title="Лимиты сервера">
              <div className="panel-body">
                {Object.keys(resource.data.limits).length ? (
                  <Definition
                    items={Object.entries(resource.data.limits).map(
                      ([key, value]) => [
                        key,
                        typeof value === "object"
                          ? pretty(value)
                          : String(value),
                      ],
                    )}
                  />
                ) : (
                  <p className="muted">
                    Лимиты не переданы API. Максимальный размер тела запроса
                    интерфейса — 1 МиБ.
                  </p>
                )}
              </div>
            </Panel>
          </>
        )
      )}
      <div className="section-heading">
        <h2>Не реализовано</h2>
        <span className="muted">Не доступно для запуска</span>
      </div>
      <div className="mode-grid mode-grid-future">
        {futureModes.map((mode) => (
          <article className="mode-card" key={mode.title}>
            <ShieldOff size={23} />
            <Badge value="not_implemented" />
            <h3>{mode.title}</h3>
            <p>{mode.detail}</p>
          </article>
        ))}
      </div>
      <Notice>
        Совместимость при подключении к конкретному кластеру, Keycloak или Dex
        не подтверждена этим интерфейсом. Наличие провайдера в конфигурации не
        означает успешного подключения.
      </Notice>
    </>
  );
}

export function AuditPage() {
  const [offset, setOffset] = useState(0);
  const resource = useResource<AuditEvent[]>(`/audit?offset=${offset}`);
  return (
    <>
      <PageHeader
        title="Журнал действий"
        description="Административный журнал API: кто, когда и какое действие выполнил."
        action={
          <button className="button button-secondary" onClick={resource.reload}>
            <RefreshCw size={16} />
            Обновить
          </button>
        }
      />
      <ErrorBox message={resource.error} retry={resource.reload} />
      {resource.loading && !resource.data ? (
        <Spinner />
      ) : resource.data?.length ? (
        <Panel
          title="События аудита"
          action={
            <span className="small muted">{resource.data.length} событий</span>
          }
        >
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Пользователь</th>
                  <th>Действие</th>
                  <th>Объект</th>
                  <th>Подробности</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.map((event) => (
                  <tr key={event.id}>
                    <td className="nowrap cell-secondary">
                      {formatDate(event.created_at)}
                    </td>
                    <td>{event.actor}</td>
                    <td>
                      <code>{event.action}</code>
                    </td>
                    <td className="break-word">{event.target || "—"}</td>
                    <td>
                      <details className="inline-details">
                        <summary>Открыть</summary>
                        <pre>
                          {typeof event.detail === "string"
                            ? event.detail
                            : pretty(event.detail)}
                        </pre>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : (
        resource.data && (
          <Panel title="События аудита">
            <EmptyState
              icon={<Fingerprint size={30} />}
              title="Событий пока нет"
            >
              В журнале появятся действия пользователей. Секреты и учётные
              данные не должны записываться в события.
            </EmptyState>
          </Panel>
        )
      )}
      <Pagination
        offset={offset}
        count={resource.data?.length}
        loading={resource.loading}
        onChange={setOffset}
      />
    </>
  );
}
