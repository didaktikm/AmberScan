import type { Disposition, Role, Run } from "./types";

export const roleLabels: Record<Role, string> = {
  administrator: "Администратор",
  auditor: "Аудитор",
  viewer: "Наблюдатель",
  security_lead: "Руководитель ИБ",
};
export const dispositionLabels: Record<Disposition, string> = {
  open: "Не рассмотрено",
  confirmed: "Подтверждено",
  accepted_risk: "Риск принят",
  false_positive: "Ложное срабатывание",
};
export const severityLabels: Record<string, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  info: "Информация",
  unknown: "Не определена",
};
export const statusLabels: Record<string, string> = {
  queued: "В очереди",
  running: "Выполняется",
  completed: "Завершено",
  partial: "Частичное покрытие",
  failed: "Ошибка",
  cancelled: "Отменено",
  interrupted: "Прервано",
  denied: "Нет доступа",
  error: "Ошибка",
  not_checked: "Не проверено",
  unsupported: "Не поддерживается",
  authorization_required: "Нужна авторизация",
  offline: "Не в сети",
  idle: "Ожидает заданий",
  busy: "Занят",
  authorized: "Авторизован",
  connected: "Подключён",
  ready: "Готов",
  pending: "Нужна авторизация",
  unauthorized: "Нужна авторизация",
  expired: "Срок истёк",
  disconnected: "Отключён",
  credential_missing: "Нет учётных данных",
  available: "Доступно",
  implemented: "Реализовано",
  limited: "С ограничениями",
  import_only: "Только импорт",
  unavailable: "Недоступно",
  not_implemented: "Не реализовано",
  planned: "Не реализовано",
  disabled: "Отключено",
  enabled: "Включён",
  passed: "Проверка пройдена",
};
export const stageLabels: Record<string, string> = {
  queued: "Ожидание обработчика",
  preflight: "Проверка доступа",
  execute: "Сбор и проверка конфигурации",
  normalize: "Нормализация результатов",
  cleanup: "Завершение",
  imported: "Импорт отчёта",
};
export function canScan(role: Role) {
  return (
    role === "administrator" || role === "auditor" || role === "security_lead"
  );
}
export function canManage(role: Role) {
  return role === "administrator";
}
export function canAcceptRisk(role: Role) {
  return role === "administrator" || role === "security_lead";
}
export function dispositionOptions(role: Role): Disposition[] {
  return canAcceptRisk(role)
    ? ["open", "confirmed", "accepted_risk", "false_positive"]
    : role === "auditor"
      ? ["confirmed"]
      : [];
}
export function parseNamespaces(input: string): string[] {
  const namespaces = [
    ...new Set(
      input
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ];
  if (!namespaces.length)
    throw new Error(
      "Укажите хотя бы одно пространство имён. Область проверки не выбирается автоматически.",
    );
  if (namespaces.length > 100)
    throw new Error(
      "В одной области допускается не более 100 пространств имён.",
    );
  if (
    namespaces.some(
      (s) => s.length > 63 || !/^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(s),
    )
  ) {
    throw new Error(
      "Имя пространства имён: строчные латинские буквы, цифры и дефисы, до 63 символов. Маски и «все пространства имён» не допускаются.",
    );
  }
  return namespaces;
}
export function formatDate(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Некорректная дата"
    : new Intl.DateTimeFormat("ru-RU", {
        dateStyle: "short",
        timeStyle: "medium",
      }).format(date);
}
export function elapsed(
  run: Pick<Run, "started_at" | "finished_at" | "status">,
  now = Date.now(),
) {
  if (!run.started_at) return "Не начат";
  if (!run.finished_at && !["running", "queued"].includes(run.status))
    return "Время завершения не передано";
  const start = Date.parse(run.started_at);
  const end = run.finished_at ? Date.parse(run.finished_at) : now;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start)
    return "—";
  const seconds = Math.floor((end - start) / 1000);
  if (seconds >= 3600)
    return `${Math.floor(seconds / 3600)} ч ${Math.floor((seconds % 3600) / 60)} мин`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)} мин ${seconds % 60} с`;
  return `${seconds} с`;
}
export function isActive(run: Run) {
  return run.status === "queued" || run.status === "running";
}
export function shortId(value: string) {
  return value.slice(0, 8);
}
export function pretty(value: unknown) {
  return JSON.stringify(value, null, 2) ?? "—";
}
export function credentialValid(expires?: string | null) {
  return !!expires && Date.parse(expires) > Date.now();
}
