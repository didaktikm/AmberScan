import type { Session } from "./types";
import { domainErrorMessage, validationErrorMessage } from "./apiErrorMessages";

export const MAX_BODY_BYTES = 1_048_576;
export const MAX_FILE_BYTES = 900_000;
export const MAX_KUBECONFIG_BYTES = 262_144;
let csrfToken: string | null = null;
let unauthorized: (() => void) | undefined;

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status = 0,
    public readonly code = "network_error",
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function setSession(session: Session | null) {
  csrfToken = session?.csrf_token || null;
}
export function onUnauthorized(handler?: () => void) {
  unauthorized = handler;
}

export function errorText(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "Не удалось выполнить запрос. Повторите попытку.";
}

export function parseApiError(payload: unknown, status: number): ApiError {
  const fallback =
    status === 401
      ? "Сессия завершена. Войдите снова."
      : status === 403
        ? "Недостаточно прав для этого действия."
        : status === 404
          ? "Объект не найден или недоступен для вашей роли."
          : status === 413
            ? "Файл или тело запроса превышает допустимый размер."
            : status >= 500
              ? "Сервис не смог обработать запрос. Проверьте состояние сервера и повторите попытку."
              : `Запрос не выполнен (HTTP ${status}).`;
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "string")
      return new ApiError(detail, status, "api_error");
    if (Array.isArray(detail)) {
      const messages = detail.slice(0, 8).map(validationErrorMessage);
      return new ApiError(messages.join(" "), status, "validation_error");
    }
    if (
      detail &&
      typeof detail === "object" &&
      "message" in detail &&
      typeof detail.message === "string"
    ) {
      const code =
        "code" in detail && typeof detail.code === "string"
          ? detail.code
          : "api_error";
      return new ApiError(
        domainErrorMessage(code, detail.message),
        status,
        code,
      );
    }
  }
  return new ApiError(fallback, status, "api_error");
}

export function apiPath(path: string) {
  if (
    !/^\/(?!\/)/.test(path) ||
    /[\\#\u0000- ]/.test(path) ||
    path
      .split("?")[0]
      .split("/")
      .some((part) => part === ".." || part === ".")
  ) {
    throw new ApiError(
      "Разрешены только относительные пути API.",
      0,
      "invalid_path",
    );
  }
  return `/api${path}`;
}

export function queryString(
  values: Record<string, string | undefined>,
): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values))
    if (value?.trim()) params.set(key, value.trim());
  const result = params.toString();
  return result ? `?${result}` : "";
}

interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  signal?: AbortSignal;
}

async function request(
  path: string,
  options: RequestOptions = {},
): Promise<Response> {
  const url = apiPath(path);
  const method = options.method ?? "GET";
  const headers = new Headers({ Accept: "application/json" });
  if (method !== "GET" && path !== "/login") {
    if (!csrfToken)
      throw new ApiError(
        "Сессия не подтверждена. Войдите снова.",
        401,
        "csrf_missing",
      );
    headers.set("X-CSRF-Token", csrfToken);
  }
  let body: string | undefined;
  if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    if (new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) {
      throw new ApiError(
        "Запрос превышает 1 МиБ. Выберите меньший файл или отчёт.",
        413,
        "body_too_large",
      );
    }
    headers.set("Content-Type", "application/json");
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (options.signal?.aborted) controller.abort();
  else options.signal?.addEventListener("abort", abort, { once: true });
  const timeout = setTimeout(() => controller.abort(), 90_000);
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body,
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
  } catch (error) {
    if (options.signal?.aborted) throw error;
    if (controller.signal.aborted)
      throw new ApiError(
        "Сервер не ответил за 90 секунд. Состояние действия неизвестно: обновите список перед повтором.",
        0,
        "timeout",
      );
    throw new ApiError(
      "Нет соединения с API. Проверьте доступность сервера и повторите запрос. Данные не заменены демонстрационными.",
    );
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abort);
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    if (response.status === 401 && path !== "/login") {
      setSession(null);
      if (path !== "/session") unauthorized?.();
    }
    throw parseApiError(payload, response.status);
  }
  return response;
}

export async function api<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const response = await request(path, options);
  if (response.status === 204) return undefined as T;
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(
      "Сервер вернул ответ не в формате JSON. Проверьте маршрут /api и конфигурацию прокси.",
      response.status,
      "invalid_response",
    );
  }
}

export async function downloadReport(
  runId: string,
  format: "json" | "markdown" | "html",
) {
  const response = await request(
    `/runs/${encodeURIComponent(runId)}/report?format=${format}`,
  );
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `amberdata-${runId.replace(/[^a-zA-Z0-9-]/g, "")}.${format === "markdown" ? "md" : format}`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  // Keep the object URL long enough for the browser to begin the download.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export async function readTextFile(file: File, maxBytes = MAX_FILE_BYTES) {
  if (file.size === 0) throw new ApiError("Выбранный файл пуст.");
  if (file.size > maxBytes)
    throw new ApiError(
      maxBytes === MAX_KUBECONFIG_BYTES
        ? "Kubeconfig больше 256 КиБ. Выберите меньший файл."
        : "Файл больше 900 КБ. Лимит запроса API — 1 МиБ вместе с метаданными.",
    );
  return file.text();
}

export function parseReportJson(text: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ApiError(
      "Некорректный JSON. Выберите исходный JSON-отчёт сканера.",
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new ApiError("Корень JSON-отчёта должен быть объектом.");
  return value as Record<string, unknown>;
}
