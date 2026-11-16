const errorLabels: Record<string, string> = {
  csrf: "Не удалось подтвердить подлинность запроса. Обновите страницу и повторите действие.",
  connection_mismatch:
    "Адрес API, центр сертификации (CA) и контекст должны совпадать с сохранённым подключением.",
  kubernetes_authentication_required:
    "Kubernetes отклонил учётные данные. Повторно импортируйте kubeconfig для этого подключения.",
  namespace_snapshot_expired:
    "Срок действия списка пространств имён истёк. Обновите список.",
  invalid_namespace_continuation:
    "Не удалось продолжить загрузку пространств имён. Обновите список.",
  invalid_namespace_discovery:
    "API вернул некорректный или противоречивый список пространств имён.",
  preflight_failed: "Проверка доступа не подтвердила выбранную область.",
  preflight_partial:
    "Подтвердите сохранение области с ограничениями доступа RBAC (403).",
  credential_required: "Импортируйте личные учётные данные из kubeconfig.",
  http_tls:
    "Не удалось установить TLS-соединение или проверить сертификат сервера.",
  http_dns: "Не удалось определить IP-адрес сервера по его имени.",
  http_transport: "Не удалось установить соединение с сервером.",
  http_timeout: "Превышено время ожидания ответа сервера.",
  http_invalid_json:
    "Сервер вернул некорректный или неподдерживаемый ответ JSON.",
  http_response_too_large: "Ответ сервера превышает допустимый размер.",
  http_redirect_denied: "Перенаправление запроса сервером запрещено.",
  endpoint_denied: "Адрес сервера не разрешён политикой исходящих подключений.",
  unsupported_scanner: "Этот сканер не поддерживается.",
};

const validationLabels: Record<string, string> = {
  missing: "Обязательное поле.",
  string_type: "Введите текст.",
  string_too_short: "Значение короче допустимого.",
  string_too_long: "Значение длиннее допустимого.",
  string_pattern_mismatch: "Значение не соответствует требуемому формату.",
  int_parsing: "Введите целое число.",
  int_type: "Введите целое число.",
  int_from_float: "Введите целое число без дробной части.",
  float_parsing: "Введите число.",
  float_type: "Введите число.",
  bool_parsing: "Укажите логическое значение.",
  bool_type: "Укажите логическое значение.",
  list_type: "Ожидается список значений.",
  dict_type: "Ожидается объект.",
  greater_than: "Значение должно быть больше допустимой нижней границы.",
  greater_than_equal: "Значение меньше допустимого минимума.",
  less_than: "Значение должно быть меньше допустимой верхней границы.",
  less_than_equal: "Значение превышает допустимый максимум.",
  too_short: "Недостаточно элементов.",
  too_long: "Слишком много элементов.",
  literal_error: "Выберите одно из допустимых значений.",
  enum: "Выберите одно из допустимых значений.",
  extra_forbidden: "Лишнее поле не допускается.",
  json_invalid: "Некорректный формат JSON.",
};

const fieldLabels: Record<string, string> = {
  username: "Имя пользователя",
  password: "Пароль",
  name: "Название",
  namespaces: "Пространства имён",
  context: "Контекст",
  environment: "Окружение",
  server: "Адрес API",
  timeout_seconds: "Лимит времени",
  cluster_id: "Подключение",
  purpose: "Назначение",
  host: "Узел",
  port: "Порт",
  cidrs: "Сети CIDR",
  rules: "Правила",
  content: "Содержимое файла",
  report: "Отчёт",
  retention: "Режим хранения",
};

function lookup(
  labels: Record<string, string>,
  key: string,
): string | undefined {
  return Object.hasOwn(labels, key) ? labels[key] : undefined;
}

export function domainErrorMessage(code: string, message: string): string {
  // Broad codes (invalid_input, forbidden, conflict, etc.) have different causes.
  // Preserve their diagnostic message rather than inventing a more specific one.
  return lookup(errorLabels, code) ?? message;
}

export function validationErrorMessage(entry: unknown): string {
  if (!entry || typeof entry !== "object") return "Проверьте поля формы.";
  const { loc, type, msg } = entry as {
    loc?: unknown;
    type?: unknown;
    msg?: unknown;
  };
  const field = Array.isArray(loc)
    ? loc
        .filter(
          (part) =>
            part !== "body" &&
            (typeof part === "string" || typeof part === "number"),
        )
        .map((part) => lookup(fieldLabels, String(part)) ?? String(part))
        .join(".")
    : "";
  const message =
    (typeof type === "string" ? lookup(validationLabels, type) : undefined) ??
    (typeof msg === "string" ? msg : "Проверьте поля формы.");
  return `${field ? `${field}: ` : ""}${message}`;
}
