import { useState, type FormEvent } from "react";
import {
  ArrowUpRight,
  Check,
  Filter,
  RefreshCw,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import { api, errorText, queryString } from "../api";
import { useResource } from "../hooks";
import {
  Definition,
  EmptyState,
  ErrorBox,
  Modal,
  Notice,
  PageHeader,
  Pagination,
  Panel,
  Spinner,
} from "../ui";
import {
  dispositionLabels,
  dispositionOptions,
  formatDate,
  canScan,
  pretty,
  severityLabels,
  shortId,
} from "../utils";
import type { Cluster, Disposition, Finding, User } from "../types";

export function SeverityBadge({ value }: { value: string }) {
  return (
    <span className={`severity severity-${value}`}>
      <span aria-hidden="true" />
      {severityLabels[value] ?? value}
    </span>
  );
}

export function FindingDialog({
  finding,
  user,
  onClose,
  onChanged,
  openRun,
}: {
  finding: Finding;
  user: User;
  onClose: () => void;
  onChanged?: () => void;
  openRun?: (id: string) => void;
}) {
  const [disposition, setDisposition] = useState<Disposition>(
    finding.disposition || "open",
  );
  const [saved, setSaved] = useState<Disposition>(
    finding.disposition || "open",
  );
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState(false);
  const options = dispositionOptions(user.role);
  const canRemediate =
    canScan(user.role) &&
    ["Deployment", "StatefulSet", "DaemonSet"].includes(finding.resource_kind) &&
    [
      "builtin:privileged",
      "builtin:privilege-escalation",
      "builtin:root-user",
      "builtin:host-namespaces",
    ].includes(finding.rule_id);
  async function remediate() {
    setBusy(true);
    setError(undefined);
    setSuccess(false);
    try {
      await api(`/clusters/${encodeURIComponent(finding.cluster_id)}/protected-action`, {
        method: "POST",
        body: { action: "remediate", confirm: true, finding_id: finding.id },
      });
      setSuccess(true);
      onChanged?.();
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(false);
    }
  }
  async function update(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    setSuccess(false);
    try {
      await api(`/findings/${encodeURIComponent(finding.id)}`, {
        method: "PATCH",
        body: { disposition },
      });
      setSaved(disposition);
      setSuccess(true);
      onChanged?.();
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setBusy(false);
    }
  }
  const confidence =
    { high: "Высокая", medium: "Средняя", low: "Низкая" }[finding.confidence] ??
    finding.confidence;
  return (
    <Modal
      wide
      title={finding.title}
      subtitle={`Правило ${finding.rule_id} · ${finding.scanner}`}
      onClose={onClose}
    >
      <div className="form-stack">
        <div className="detail-badges">
          <SeverityBadge value={finding.severity} />
          <span className="tag">{dispositionLabels[saved]}</span>
          <span className="tag">Уверенность: {confidence}</span>
        </div>
        <Definition
          items={[
            ["Кластер", finding.cluster_name],
            ["Пространство имён", finding.namespace || "Не указано"],
            [
              "Ресурс",
              [finding.resource_kind, finding.resource_name]
                .filter(Boolean)
                .join(" / ") || "Не указан",
            ],
            ["UID ресурса", finding.resource_uid || "Не указан"],
            ["Категория", finding.category],
            ["Первое наблюдение", formatDate(finding.first_seen)],
            ["Последнее наблюдение", formatDate(finding.last_seen)],
            ...(finding.vulnerability_id
              ? [["Уязвимость", finding.vulnerability_id] as [string, string]]
              : []),
            ...(finding.package
              ? [
                  [
                    "Пакет",
                    typeof finding.package === "string"
                      ? finding.package
                      : pretty(finding.package),
                  ] as [string, string],
                ]
              : []),
            ...(finding.image_digest
              ? [["Хеш образа", finding.image_digest] as [string, string]]
              : []),
            ...(finding.location
              ? [["Расположение", finding.location] as [string, string]]
              : []),
          ]}
        />
        {finding.run_id && openRun && (
          <div>
            <button
              className="text-button"
              onClick={() => {
                onClose();
                openRun(finding.run_id);
              }}
            >
              Открыть запуск #{shortId(finding.run_id)}
              <ArrowUpRight size={15} />
            </button>
          </div>
        )}
        <section>
          <h3>Доказательства</h3>
          <p className="muted small">
            Нормализованные данные источника. Содержимое отображается как текст,
            без исполнения HTML.
          </p>
          <pre className="evidence">{pretty(finding.evidence)}</pre>
        </section>
        <section>
          <h3>Рекомендация</h3>
          <p className="recommendation">
            {finding.recommendation ||
              "Источник не предоставил рекомендацию. Проверьте правило и доказательства вручную."}
          </p>
        </section>
        {canRemediate && (
          <section className="form-stack">
            <h3>Исправление в кластере</h3>
            <p className="small muted">
              Кнопка меняет шаблон этого контроллера. Другие ресурсы не
              затрагиваются.
            </p>
            <button
              type="button"
              className="button button-secondary"
              disabled={busy}
              onClick={() => void remediate()}
            >
              Применить исправление
            </button>
          </section>
        )}
        <Notice tone="warning">
          Находка — наблюдение, а не статус устранения. Принятие риска не
          исправляет ресурс. Отсутствие находки в следующем запуске не закрывает
          её автоматически.
        </Notice>
        {options.length > 0 && finding.id ? (
          <form onSubmit={update} className="disposition-form">
            <h3>Решение по находке</h3>
            <ErrorBox message={error} />
            {success && (
              <Notice tone="success">
                Решение сохранено: {dispositionLabels[saved]}.
              </Notice>
            )}
            <div className="form-inline">
              <label>
                Решение
                <select
                  value={disposition}
                  onChange={(event) => {
                    setDisposition(event.target.value as Disposition);
                    setSuccess(false);
                  }}
                >
                  {!options.includes(saved) && (
                    <option value={saved} disabled>
                      {dispositionLabels[saved]}
                    </option>
                  )}
                  {options.map((value) => (
                    <option key={value} value={value}>
                      {dispositionLabels[value]}
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="button button-primary"
                type="submit"
                disabled={
                  busy ||
                  saved === disposition ||
                  !options.includes(disposition)
                }
              >
                <Check size={16} />
                {busy ? "Сохранение…" : "Сохранить решение"}
              </button>
            </div>
            {user.role === "auditor" && (
              <p className="small muted">
                Аудитор может только подтвердить находку. Принятие риска и
                ложное срабатывание доступны руководителю ИБ или администратору.
              </p>
            )}
            {["accepted_risk", "false_positive"].includes(disposition) && (
              <p className="small warning-text">
                Вы меняете оценку наблюдения. Это решение будет записано в
                журнал действий.
              </p>
            )}
          </form>
        ) : (
          <p className="muted small">
            Для вашей роли изменение решения недоступно. Проверка прав
            выполняется сервером.
          </p>
        )}
      </div>
    </Modal>
  );
}

export function FindingTable({
  findings,
  onSelect,
}: {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Критичность</th>
            <th>Находка / правило</th>
            <th>Ресурс</th>
            <th>Источник</th>
            <th>Решение</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={finding.id ?? `${finding.rule_id}-${index}`}>
              <td>
                <SeverityBadge value={finding.severity} />
              </td>
              <td className="finding-title-cell">
                <button
                  className="table-link"
                  onClick={() => onSelect(finding)}
                >
                  {finding.title}
                  <span>{finding.rule_id}</span>
                </button>
              </td>
              <td>
                <span className="cell-primary break-word">
                  {finding.resource_name || "Не указан"}
                </span>
                <span className="cell-subtext">
                  {[
                    finding.cluster_name,
                    finding.namespace,
                    finding.resource_kind,
                  ]
                    .filter(Boolean)
                    .join(" / ") || "Область не указана"}
                </span>
              </td>
              <td>
                <span className="tag">{finding.scanner}</span>
              </td>
              <td>
                <span className="disposition-label">
                  {dispositionLabels[finding.disposition] ?? "Не рассмотрено"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function FindingsPage({
  user,
  openRun,
  initialCluster = "",
}: {
  user: User;
  openRun: (id: string) => void;
  initialCluster?: string;
}) {
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [cluster, setCluster] = useState(initialCluster);
  const [severity, setSeverity] = useState("");
  const [disposition, setDisposition] = useState("");
  const [appliedQuery, setAppliedQuery] = useState("");
  const [selected, setSelected] = useState<Finding>();
  const clusters = useResource<Cluster[]>("/clusters");
  const findings = useResource<Finding[]>(
    `/findings${queryString({ cluster_id: cluster, severity, q: appliedQuery, offset: String(offset) })}`,
  );
  const shown = findings.data?.filter(
    (finding) => !disposition || finding.disposition === disposition,
  );
  const filtered = !!(cluster || severity || disposition || appliedQuery);
  function clear() {
    setOffset(0);
    setQuery("");
    setAppliedQuery("");
    setCluster("");
    setSeverity("");
    setDisposition("");
  }
  return (
    <>
      <PageHeader
        title="Находки"
        description="Доказательства, происхождение и решения по результатам проверок."
        action={
          <button className="button button-secondary" onClick={findings.reload}>
            <RefreshCw size={16} />
            Обновить
          </button>
        }
      />
      <form
        className="filter-bar"
        onSubmit={(event) => {
          event.preventDefault();
          setOffset(0);
          setAppliedQuery(query);
          findings.reload();
        }}
      >
        <label className="search-field">
          <span>Поиск по находкам</span>
          <div>
            <Search size={17} />
            <input
              type="search"
              value={query}
              maxLength={200}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Название, правило или ресурс"
            />
          </div>
        </label>
        <label>
          Кластер
          <select
            value={cluster}
            onChange={(event) => {
              setOffset(0);
              setCluster(event.target.value);
            }}
          >
            <option value="">Все доступные</option>
            {clusters.data?.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Критичность
          <select
            value={severity}
            onChange={(event) => {
              setOffset(0);
              setSeverity(event.target.value);
            }}
          >
            <option value="">Любая</option>
            {Object.entries(severityLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Решение на странице
          <select
            value={disposition}
            onChange={(event) => setDisposition(event.target.value)}
          >
            <option value="">Любое</option>
            {Object.entries(dispositionLabels).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <button className="button button-secondary" type="submit">
          <Filter size={16} />
          Найти
        </button>
      </form>
      <ErrorBox message={findings.error} retry={findings.reload} />
      <ErrorBox message={clusters.error} retry={clusters.reload} />
      <Panel
        title="Результаты"
        action={
          <div className="button-row">
            <span className="small muted">
              {shown ? `${shown.length} находок` : "Загрузка"}
            </span>
            {filtered && (
              <button className="text-button" onClick={clear}>
                <X size={13} />
                Сбросить фильтры
              </button>
            )}
          </div>
        }
      >
        {findings.loading && !findings.data ? (
          <Spinner />
        ) : shown?.length ? (
          <FindingTable findings={shown} onSelect={setSelected} />
        ) : (
          shown && (
            <EmptyState
              icon={<ShieldCheck size={31} />}
              title={
                filtered
                  ? "По этим фильтрам ничего не найдено"
                  : "Находок пока нет"
              }
            >
              {filtered
                ? "Измените запрос, критичность или решение. Данные ограничены доступными вам кластерами."
                : "Запустите проверку или импортируйте отчёт. Пустой список не подтверждает безопасность — учитывайте покрытие и ограничения."}
            </EmptyState>
          )
        )}
      </Panel>
      <Pagination
        offset={offset}
        count={findings.data?.length}
        loading={findings.loading}
        onChange={setOffset}
      />
      <Notice>
        Критичность и уверенность поступают из источника. Статус «подтверждено»
        означает решение аналитика, а не исправление проблемы.
      </Notice>
      {selected && (
        <FindingDialog
          key={selected.id}
          finding={selected}
          user={user}
          onClose={() => setSelected(undefined)}
          onChanged={findings.reload}
          openRun={openRun}
        />
      )}
    </>
  );
}
