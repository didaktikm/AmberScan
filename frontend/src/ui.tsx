import { useEffect, useId, useRef, type ReactNode } from "react";
import {
  AlertCircle,
  AlertTriangle,
  Check,
  ChevronLeft,
  ChevronRight,
  Circle,
  Clock3,
  Info,
  LoaderCircle,
  RefreshCw,
  ShieldOff,
  X,
} from "lucide-react";
import { statusLabels } from "./utils";
import type { Coverage } from "./types";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? "brand-compact" : ""}`}>
      <span className="brand-symbol" aria-hidden="true">
        <svg viewBox="0 0 40 40">
          <path
            d="M9 30 18 9h5l9 21h-7l-1.5-4h-7L15 30zm9-10h4l-2-6z"
            fill="currentColor"
          />
        </svg>
      </span>
      <div>
        <strong>AmberData</strong>
        {!compact && <span>Kubernetes Workbench</span>}
      </div>
    </div>
  );
}
export function Spinner({ label = "Загрузка данных…" }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <LoaderCircle className="spin" size={18} aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}
export function ErrorBox({
  message,
  retry,
}: {
  message?: string;
  retry?: () => void;
}) {
  if (!message) return null;
  return (
    <div className="notice notice-error" role="alert">
      <AlertCircle size={19} aria-hidden="true" />
      <div>
        <strong>Не удалось выполнить действие</strong>
        <p>{message}</p>
      </div>
      {retry && (
        <button
          className="button button-small button-secondary"
          type="button"
          onClick={retry}
        >
          <RefreshCw size={14} />
          Повторить
        </button>
      )}
    </div>
  );
}
export function Notice({
  children,
  tone = "info",
}: {
  children: ReactNode;
  tone?: "info" | "warning" | "success";
}) {
  const Icon =
    tone === "warning" ? AlertTriangle : tone === "success" ? Check : Info;
  return (
    <div
      className={`notice notice-${tone}`}
      role={tone === "success" ? "status" : undefined}
    >
      <Icon size={18} aria-hidden="true" />
      <div>{children}</div>
    </div>
  );
}
export function EmptyState({
  icon,
  title,
  children,
  action,
}: {
  icon?: ReactNode;
  title: string;
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon" aria-hidden="true">
        {icon ?? <Circle size={28} />}
      </div>
      <h3>{title}</h3>
      <p>{children}</p>
      {action}
    </div>
  );
}
export function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="heading-action">{action}</div>}
    </div>
  );
}
export function Badge({ value }: { value: string }) {
  const good = [
    "completed",
    "authorized",
    "connected",
    "ready",
    "available",
    "implemented",
    "passed",
  ].includes(value);
  const bad = ["failed", "error", "denied", "critical", "high"].includes(value);
  const warn = [
    "partial",
    "expired",
    "limited",
    "medium",
    "import_only",
    "interrupted",
  ].includes(value);
  const active = ["queued", "running"].includes(value);
  const Icon = good
    ? Check
    : bad
      ? AlertCircle
      : warn
        ? AlertTriangle
        : active
          ? Clock3
          : ["unsupported", "unavailable", "not_implemented"].includes(value)
            ? ShieldOff
            : Circle;
  return (
    <span
      className={`badge ${good ? "badge-good" : bad ? "badge-bad" : warn ? "badge-warn" : active ? "badge-active" : "badge-neutral"}`}
    >
      <Icon size={12} aria-hidden="true" />
      {statusLabels[value] ?? value}
    </span>
  );
}
export function Modal({
  title,
  subtitle,
  onClose,
  children,
  wide = false,
  busy = false,
}: {
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const heading = useId();
  const description = useId();
  useEffect(() => {
    const dialog = ref.current;
    const previous = document.activeElement as HTMLElement | null;
    dialog?.showModal();
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      dialog?.close();
      document.body.style.overflow = overflow;
      previous?.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={`modal ${wide ? "modal-wide" : ""}`}
      aria-labelledby={heading}
      aria-describedby={subtitle ? description : undefined}
      onCancel={(event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!busy) onClose();
      }}
    >
      <div className="modal-header">
        <div>
          <h2 id={heading}>{title}</h2>
          {subtitle && <p id={description}>{subtitle}</p>}
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={onClose}
          disabled={busy}
          aria-label="Закрыть окно"
        >
          <X size={20} />
        </button>
      </div>
      <div className="modal-content">{children}</div>
    </dialog>
  );
}
export function CoverageTable({ coverage }: { coverage?: Coverage[] }) {
  if (!coverage?.length)
    return (
      <Notice>
        Данные о покрытии ещё не получены. Это не означает, что все проверки
        пройдены.
      </Notice>
    );
  return (
    <div className="table-scroll">
      <table>
        <caption className="sr-only">
          Покрытие проверок и ограничения доступа
        </caption>
        <thead>
          <tr>
            <th>Проверка / ресурс</th>
            <th>Результат</th>
            <th>Подробности</th>
          </tr>
        </thead>
        <tbody>
          {coverage.map((item, index) => (
            <tr key={`${item.check}-${index}`}>
              <td className="cell-primary break-word">
                {item.namespace && (
                  <span className="cell-subtext">
                    Пространство имён: {item.namespace}
                  </span>
                )}
                {item.resource || item.check}
                {item.verb && (
                  <span className="cell-subtext">
                    {item.group || "core"} · {item.verb}
                  </span>
                )}
              </td>
              <td>
                <Badge value={item.status} />
              </td>
              <td className="cell-secondary break-word">
                {item.detail || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function Definition({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="definition">
      {items.map(([title, value]) => (
        <div key={title}>
          <dt>{title}</dt>
          <dd>{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
export const PAGE_SIZE = 500;
export function Pagination({
  offset,
  count,
  loading,
  onChange,
}: {
  offset: number;
  count?: number;
  loading: boolean;
  onChange: (offset: number) => void;
}) {
  return (
    <div className="pagination">
      <span>
        Страница {Math.floor(offset / PAGE_SIZE) + 1} · до {PAGE_SIZE} записей
        API{count !== undefined ? ` · получено ${count}` : ""}
      </span>
      <div className="button-row">
        <button
          className="button button-small button-secondary"
          disabled={loading || offset === 0}
          onClick={() => onChange(Math.max(0, offset - PAGE_SIZE))}
        >
          <ChevronLeft size={14} />
          Назад
        </button>
        <button
          className="button button-small button-secondary"
          disabled={loading || count !== PAGE_SIZE}
          onClick={() => onChange(offset + PAGE_SIZE)}
        >
          Далее
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  );
}
export function Panel({
  title,
  action,
  children,
  className = "",
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-header">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}
