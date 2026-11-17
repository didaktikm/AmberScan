import { useEffect, useId, useRef, useState } from "react";
import { RefreshCw } from "lucide-react";
import { addNamespaces, isSystemNamespace, MAX_NAMESPACES } from "./namespaces";
import { errorText } from "./api";
import { parseNamespaces } from "./utils";
import { ErrorBox, Notice } from "./ui";
import type { NamespaceOption } from "./types";

interface Props {
  selected: string[];
  onChange: (names: string[]) => void;
  options: NamespaceOption[];
  label?: string;
  hint?: string | null;
  disabled?: boolean;
  loading?: boolean;
  onRefresh?: () => void;
  onLoadMore?: () => void;
  /** An absent result is not an empty, successful list. */
  loaded?: boolean;
  complete?: boolean;
  stale?: boolean;
  forbidden?: boolean;
  limitation?: string | null;
  allowlist?: string[];
  savedNames?: string[];
}

export function NamespacePicker({
  selected,
  onChange,
  options,
  label = "Пространства имён",
  hint,
  disabled = false,
  loading = false,
  onRefresh,
  onLoadMore,
  loaded = true,
  complete = true,
  stale = false,
  forbidden = false,
  limitation,
  allowlist,
  savedNames,
}: Props) {
  const id = useId();
  const [filter, setFilter] = useState("");
  const [manual, setManual] = useState("");
  // A fresh object retriggers the reveal even for the same invalid submission.
  const [error, setError] = useState<{ message: string }>();
  const errorRef = useRef<HTMLDivElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const alert = errorRef.current;
    const scroll = scrollRef.current;
    if (!error || !alert || !scroll) return;
    const alertBounds = alert.getBoundingClientRect();
    const scrollBounds = scroll.getBoundingClientRect();
    // Scroll only the picker, never the surrounding modal or page.
    if (
      alertBounds.top < scrollBounds.top ||
      alertBounds.bottom > scrollBounds.bottom
    ) {
      scroll.scrollTop += alertBounds.top - scrollBounds.top - 4;
    }
  }, [error]);
  const seen = useRef(new Set<string>());
  for (const option of options) seen.current.add(option.name);
  const names = new Set(options.map((item) => item.name));
  const rows: NamespaceOption[] = [
    ...options,
    ...selected
      .filter((name) => !names.has(name))
      .map((name) => ({ name, system: isSystemNamespace(name) })),
  ];
  const query = filter.trim().toLowerCase();
  const visible = rows.filter((item) => item.name.includes(query));
  const filtered = options.filter((item) => item.name.includes(query));
  const hiddenSelected = selected.filter(
    (name) => !name.includes(query),
  ).length;
  function change(next: string[]) {
    setError(undefined);
    onChange(next);
  }
  function add(values: string[]) {
    try {
      change(addNamespaces(selected, values, allowlist));
    } catch (reason) {
      setError({ message: errorText(reason) });
    }
  }
  function addManual() {
    try {
      const next = addNamespaces(selected, parseNamespaces(manual), allowlist);
      change(next);
      setManual("");
    } catch (reason) {
      setError({ message: errorText(reason) });
    }
  }
  return (
    <fieldset
      className="namespace-picker"
      disabled={disabled}
      aria-describedby={`${id}-help`}
    >
      <legend>{label}</legend>
      <div className="namespace-picker-layout">
        <div className="namespace-picker-header">
          <div className="namespace-toolbar">
            <label>
              Поиск пространства имён
              <input
                type="search"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              />
            </label>
            {onRefresh && (
              <button
                className="button button-secondary"
                type="button"
                onClick={onRefresh}
                disabled={disabled || loading}
              >
                <RefreshCw size={15} />
                {loading ? "Загружаем список…" : "Обновить список"}
              </button>
            )}
          </div>
          <p className="small" role="status" aria-live="polite">
            Выбрано {selected.length} из {MAX_NAMESPACES} · Загружено{" "}
            {options.length} · Показано {visible.length}
            {hiddenSelected > 0 && ` · Выбрано вне фильтра: ${hiddenSelected}`}
          </p>
        </div>
        <div
          className="namespace-picker-scroll"
          ref={scrollRef}
          role="region"
          aria-label="Выбор пространств имён"
          tabIndex={0}
        >
          <p className="small muted" id={`${id}-help`}>
            Выбирайте имена явно. Поиск и обновление списка не меняют выбор.
            Можно выбрать не более {MAX_NAMESPACES} пространств имён, но
            просматривать список можно без этого ограничения. Выбор определяет
            разрешённые пространства имён в приложении, не создаёт RoleBinding и
            не расширяет права Kubernetes.
            {allowlist &&
              " Доступны только пространства имён, сохранённые в подключении."}
          </p>
          {hint && (
            <Notice>
              Пространство имён из контекста: <strong>{hint}</strong>. Это
              подсказка, а не автоматический выбор или подтверждение доступа.
            </Notice>
          )}
          {error && (
            <div ref={errorRef}>
              <ErrorBox message={error.message} />
            </div>
          )}
          {stale && (
            <Notice tone="warning">
              Показан предыдущий список: актуальность не подтверждена.
              Обновление не завершено или завершилось ошибкой. Выбор сохранён,
              но требует повторной проверки.
            </Notice>
          )}
          {forbidden ? (
            <Notice tone="warning">
              Kubernetes запретил получение списка пространств имён (403). Это
              не означает, что кластер пуст. Укажите известные имена вручную; их
              существование не подтверждено.
            </Notice>
          ) : !loaded ? (
            <Notice>
              Список пространств имён ещё не получен. Сначала запустите
              получение списка; автоматического выбора нет.
            </Notice>
          ) : !complete ? (
            <Notice tone="warning">
              Загружен неполный список. «Все загруженные» не означает все
              пространства имён кластера. {limitation}
            </Notice>
          ) : null}
          <div className="button-row">
            <button
              type="button"
              className="button button-small button-secondary"
              disabled={disabled || !options.length}
              onClick={() => add(options.map((item) => item.name))}
            >
              Выбрать все загруженные ({options.length})
            </button>
            {query && (
              <button
                type="button"
                className="button button-small button-secondary"
                disabled={disabled || !filtered.length}
                onClick={() => add(filtered.map((item) => item.name))}
              >
                Выбрать по фильтру ({filtered.length})
              </button>
            )}
            <button
              type="button"
              className="text-button"
              disabled={disabled || !selected.length}
              onClick={() => change([])}
            >
              Снять выделение
            </button>
          </div>
          <div
            className="namespace-list"
            role="group"
            aria-label="Список пространств имён"
          >
            {visible.map((item) => {
              const absent = !names.has(item.name);
              const disallowed = allowlist && !allowlist.includes(item.name);
              return (
                <label className="namespace-row" key={item.name}>
                  <input
                    type="checkbox"
                    aria-label={`Пространство имён ${item.name}`}
                    checked={selected.includes(item.name)}
                    onChange={(event) =>
                      event.target.checked
                        ? add([item.name])
                        : change(selected.filter((name) => name !== item.name))
                    }
                  />
                  <span className="namespace-name">{item.name}</span>
                  {isSystemNamespace(item.name) && (
                    <span className="tag">Системное</span>
                  )}
                  {item.phase && (
                    <span className="tag">
                      {item.phase === "Active"
                        ? "Активно"
                        : item.phase === "Terminating"
                          ? "Удаляется"
                          : item.phase}
                    </span>
                  )}
                  {absent && (
                    <span className="namespace-warning">
                      {disallowed
                        ? "Больше не разрешено"
                        : seen.current.has(item.name)
                          ? loaded && complete && !forbidden && !stale
                            ? "Не найдено в обновлённом списке"
                            : "Не подтверждено текущим неполным списком"
                          : savedNames?.includes(item.name)
                            ? "Сохранённое пространство имён; наличие не подтверждено полученным списком"
                            : "Введено вручную"}{" "}
                      · существование не подтверждено
                    </span>
                  )}
                </label>
              );
            })}
            {!visible.length && (
              <p className="small muted namespace-empty">
                {query
                  ? "Нет совпадений. Выбор вне фильтра сохранён."
                  : loaded && complete && !forbidden
                    ? "Получен пустой список. Ни одно пространство имён не выбрано."
                    : "Нет загруженных имён. Ручной ввод доступен ниже."}
              </p>
            )}
          </div>
          {onLoadMore && (
            <button
              type="button"
              className="button button-secondary"
              disabled={disabled || loading || stale}
              onClick={onLoadMore}
            >
              Загрузить ещё пространства имён
            </button>
          )}
          <details className="namespace-manual">
            <summary>Ручной ввод пространств имён</summary>
            <label>
              Имена через запятую или с новой строки
              <textarea
                rows={2}
                value={manual}
                onChange={(event) => setManual(event.target.value)}
              />
            </label>
            <p className="small muted">
              Ручной ввод добавляет имена к выбору, не заменяя скрытые поиском.
              Успешный запрос с пустым списком ресурсов не доказывает
              существование пространства имён.
            </p>
            <button
              className="button button-small button-secondary"
              type="button"
              disabled={disabled || !manual.trim()}
              onClick={addManual}
            >
              Добавить к выбору
            </button>
          </details>
        </div>
      </div>
    </fieldset>
  );
}
