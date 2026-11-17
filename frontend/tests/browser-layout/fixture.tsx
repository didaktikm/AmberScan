// Synthetic-only root: import real presentational components, never App/auth/API routes.
import { useState } from "react";
import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { NamespacePicker } from "../../src/NamespacePicker";
import { Modal, Notice } from "../../src/ui";
import "../../src/styles.css";

type Config = { width: number; height: number; theme: "light" | "dark" };
const config = (window as unknown as { fixtureConfig: Config }).fixtureConfig;
document.documentElement.dataset.theme = config.theme;
const root = createRoot(document.getElementById("fixture-root")!);
const longName = `namespace-${"a".repeat(53)}`; // Exactly Kubernetes' 63-character limit.
const options = Array.from({ length: 140 }, (_, index) => ({
  name:
    index === 0
      ? longName
      : `team-${String(index).padStart(3, "0")}-${"b".repeat(54)}`,
  phase: index % 7 ? "Active" : "Terminating",
  system: false,
}));
const saved = `saved-${"c".repeat(57)}`;
const checks: { name: string; pass: boolean; detail?: unknown }[] = [];
const snapshots: Record<string, unknown>[] = [];
function check(name: string, pass: boolean, detail?: unknown) {
  checks.push({ name, pass, ...(detail === undefined ? {} : { detail }) });
}
function get<T extends HTMLElement = HTMLElement>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Missing fixture element: ${selector}`);
  return element;
}
function click(element: HTMLElement) {
  flushSync(() => element.click());
}
function input(element: HTMLInputElement | HTMLTextAreaElement, value: string) {
  const prototype =
    element instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  flushSync(() => {
    Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(
      element,
      value,
    );
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  });
}
function Fixture({ modal = false }: { modal?: boolean }) {
  const [selected, setSelected] = useState([longName, saved]);
  const [count, setCount] = useState(90);
  const content = (
    <div className="form-stack">
      <NamespacePicker
        selected={selected}
        onChange={setSelected}
        options={options.slice(0, count)}
        savedNames={[saved]}
        hint={longName}
        stale
        complete={false}
        limitation="Продолжение списка временно недоступно; сохранённые пространства имён требуют проверки."
        onRefresh={() => {}}
        onLoadMore={() => setCount(140)}
      />
      <button type="button" id="grow-fixture" onClick={() => setCount(140)}>
        Добавить строки фикстуры
      </button>
      <Notice tone="warning">
        Синтетические данные: подключение к Kubernetes отсутствует.
        Дополнительное длинное предупреждение для проверки переноса текста и
        прокрутки формы.
      </Notice>
      <div className="modal-footer">
        <button type="button" className="button button-secondary">
          Вернуться к настройке подключения и проверить введённые параметры
        </button>
        <button type="button" className="button button-primary">
          Сохранить выбранные пространства имён и продолжить настройку
          подключения
        </button>
      </div>
      <output id="selected-fixture" hidden>
        {JSON.stringify(selected)}
      </output>
    </div>
  );
  return modal ? (
    <Modal
      wide
      title="Настройка разрешённых пространств имён для подключения"
      subtitle="Проверка длинного пояснения: выбор не расширяет права доступа Kubernetes."
      onClose={() => {}}
    >
      {content}
    </Modal>
  ) : (
    <main style={{ padding: 16, maxWidth: 1000, marginInline: "auto" }}>
      {content}
    </main>
  );
}
function geometry(stage: string) {
  const layout = get(".namespace-picker-layout");
  const scroll = get(".namespace-picker-scroll");
  const cap = Math.min(
    34 * parseFloat(getComputedStyle(document.documentElement).fontSize),
    innerHeight * 0.65,
  );
  const pickerRect = get(".namespace-picker").getBoundingClientRect();
  const height = layout.getBoundingClientRect().height;
  const rows = [...document.querySelectorAll<HTMLElement>(".namespace-row")];
  const badRows = rows.filter((row) => {
    const checkbox = row.querySelector("input")!.getBoundingClientRect();
    const name = row.querySelector(".namespace-name")!.getBoundingClientRect();
    return (
      checkbox.right > name.left + 1 ||
      checkbox.top >= name.bottom ||
      checkbox.bottom <= name.top
    );
  });
  check(
    `${stage}: actual viewport`,
    innerWidth === config.width && innerHeight === config.height,
    { width: innerWidth, height: innerHeight },
  );
  check(
    `${stage}: document no horizontal overflow`,
    document.documentElement.scrollWidth <= innerWidth + 1,
    document.documentElement.scrollWidth,
  );
  check(`${stage}: selector cap`, height <= cap + 1, { height, cap });
  check(
    `${stage}: selector fits viewport width`,
    pickerRect.left >= -1 && pickerRect.right <= innerWidth + 1,
  );
  check(
    `${stage}: inner no horizontal overflow`,
    scroll.scrollWidth <= scroll.clientWidth + 1,
    { width: scroll.clientWidth, scrollWidth: scroll.scrollWidth },
  );
  check(`${stage}: checkbox and name side by side`, badRows.length === 0, {
    rows: rows.length,
    bad: badRows.length,
    firstFailure: badRows[0]
      ? {
          row: badRows[0].getBoundingClientRect().toJSON(),
          checkbox: badRows[0]
            .querySelector("input")!
            .getBoundingClientRect()
            .toJSON(),
          name: badRows[0]
            .querySelector(".namespace-name")!
            .getBoundingClientRect()
            .toJSON(),
        }
      : undefined,
  });
  check(
    `${stage}: list is not nested scroll container`,
    !/auto|scroll/.test(getComputedStyle(get(".namespace-list")).overflowY),
  );
  snapshots.push({
    stage,
    selectorHeight: pickerRect.height,
    cappedLayoutHeight: height,
    cap,
    scrollHeight: scroll.scrollHeight,
    scrollClientHeight: scroll.clientHeight,
    rows: rows.length,
  });
  return height;
}
function selected(): string[] {
  return JSON.parse(get("#selected-fixture").textContent!);
}
async function nextFrame() {
  await Promise.race([
    new Promise<void>((resolve) => requestAnimationFrame(() => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 50)),
  ]);
}
async function exercise(mode: "page" | "modal") {
  flushSync(() => root.render(<Fixture key={mode} modal={mode === "modal"} />));
  const initialHeight = geometry(`${mode}/many-rows`);
  const scroll = get(".namespace-picker-scroll");
  const header = get(".namespace-picker-header");
  const headerBefore = header.getBoundingClientRect().top;
  const documentBefore = document.documentElement.scrollTop;
  const parentScroll = mode === "modal" ? get(".modal-content").scrollTop : 0;
  scroll.scrollTop = scroll.scrollHeight;
  check(
    `${mode}: internal scrolling available`,
    scroll.scrollTop > 0 && scroll.clientHeight > 0,
  );
  check(
    `${mode}: header stays pinned during internal scroll`,
    Math.abs(header.getBoundingClientRect().top - headerBefore) < 1,
  );
  check(
    `${mode}: scrolling does not move document or modal`,
    document.documentElement.scrollTop === documentBefore &&
      (mode !== "modal" || get(".modal-content").scrollTop === parentScroll),
  );
  click(get(".namespace-manual summary"));
  check(
    `${mode}: manual expanded`,
    get<HTMLDetailsElement>(".namespace-manual").open,
  );
  const expandedHeight = geometry(`${mode}/manual-expanded`);
  check(
    `${mode}: expansion does not grow capped picker`,
    Math.abs(expandedHeight - initialHeight) < 1,
  );
  input(
    get<HTMLTextAreaElement>(".namespace-manual textarea"),
    "INVALID_NAMESPACE",
  );
  scroll.scrollTop = scroll.scrollHeight;
  click(get(".namespace-manual button"));
  await nextFrame();
  const alert = get('.namespace-picker [role="alert"]');
  const alertBounds = alert.getBoundingClientRect();
  const scrollBounds = scroll.getBoundingClientRect();
  check(
    `${mode}: invalid manual input reveals error in picker scrollport`,
    Math.min(alertBounds.bottom, scrollBounds.bottom) -
      Math.max(alertBounds.top, scrollBounds.top) >=
      Math.min(24, alertBounds.height),
    { alert: alertBounds.toJSON(), scrollport: scrollBounds.toJSON() },
  );
  const documentBeforeRepeat = document.documentElement.scrollTop;
  const modalBeforeRepeat =
    mode === "modal" ? get(".modal-content").scrollTop : 0;
  scroll.scrollTop = scroll.scrollHeight;
  click(get(".namespace-manual button"));
  await nextFrame();
  const repeatBounds = get(
    '.namespace-picker [role="alert"]',
  ).getBoundingClientRect();
  const repeatPort = scroll.getBoundingClientRect();
  check(
    `${mode}: repeated invalid input reveals same error`,
    Math.min(repeatBounds.bottom, repeatPort.bottom) -
      Math.max(repeatBounds.top, repeatPort.top) >=
      Math.min(24, repeatBounds.height),
  );
  check(
    `${mode}: error reveal does not move document or modal`,
    document.documentElement.scrollTop === documentBeforeRepeat &&
      (mode !== "modal" ||
        get(".modal-content").scrollTop === modalBeforeRepeat),
  );
  geometry(`${mode}/validation-warning`);
  input(
    get<HTMLInputElement>('.namespace-toolbar input[type="search"]'),
    "no-matching-namespace",
  );
  check(
    `${mode}: filter hides rows`,
    document.querySelectorAll(".namespace-row").length === 0,
  );
  check(
    `${mode}: filtering preserves selection`,
    selected().includes(longName) && selected().includes(saved),
  );
  geometry(`${mode}/empty-filter`);
  input(
    get<HTMLTextAreaElement>(".namespace-manual textarea"),
    "manual-fixture",
  );
  click(get(".namespace-manual button"));
  check(
    `${mode}: manual add preserves hidden selection`,
    selected().includes("manual-fixture") &&
      selected().includes(longName) &&
      selected().includes(saved),
  );
  input(get<HTMLInputElement>('.namespace-toolbar input[type="search"]'), "");
  geometry(`${mode}/filter-cleared`);
  const checkbox = get<HTMLInputElement>(".namespace-row input");
  const wasChecked = checkbox.checked;
  click(checkbox);
  check(
    `${mode}: checkbox interaction updates real component`,
    checkbox.checked !== wasChecked,
  );
  click(get("#grow-fixture"));
  const grownHeight = geometry(`${mode}/more-rows`);
  check(
    `${mode}: more rows do not grow capped selector`,
    Math.abs(grownHeight - initialHeight) < 1,
  );
  check(
    `${mode}: fixture actually contains 140 loaded rows`,
    document.querySelectorAll(".namespace-row").length >= 140,
  );
  if (mode === "modal") {
    const dialog = get<HTMLDialogElement>("dialog");
    const rect = dialog.getBoundingClientRect();
    const content = get(".modal-content");
    const closeRect = get(".modal-header button").getBoundingClientRect();
    check(
      "modal: native top-layer dialog open",
      dialog.open && dialog.matches(":modal"),
    );
    check(
      "modal: dialog bounded within viewport",
      rect.top >= -1 &&
        rect.bottom <= innerHeight + 1 &&
        rect.left >= -1 &&
        rect.right <= innerWidth + 1,
      {
        top: rect.top,
        bottom: rect.bottom,
        left: rect.left,
        right: rect.right,
      },
    );
    check(
      "modal: close control visible",
      closeRect.top >= 0 &&
        closeRect.bottom <= innerHeight &&
        closeRect.right <= innerWidth,
    );
    check(
      "modal: content no horizontal overflow",
      content.scrollWidth <= content.clientWidth + 1,
    );
    const headerTop = get(".modal-header").getBoundingClientRect().top;
    content.scrollTop = content.scrollHeight;
    check(
      "modal: content scrolls with header retained",
      content.scrollTop > 0 &&
        Math.abs(get(".modal-header").getBoundingClientRect().top - headerTop) <
          1,
    );
    const actions = [
      ...document.querySelectorAll<HTMLElement>(".modal-footer button"),
    ];
    check(
      "modal: long footer actions reachable and bounded",
      actions.every((action) => {
        const bounds = action.getBoundingClientRect();
        const contentBounds = content.getBoundingClientRect();
        return (
          bounds.left >= rect.left &&
          bounds.right <= rect.right &&
          bounds.top >= contentBounds.top - 1 &&
          bounds.bottom <= contentBounds.bottom + 1
        );
      }),
      actions.map((action) => ({
        width: action.clientWidth,
        scrollWidth: action.scrollWidth,
      })),
    );
    check(
      "modal: long action text not horizontally clipped",
      actions.every((action) => action.scrollWidth <= action.clientWidth + 1),
    );
  }
}
function exerciseLongTitle() {
  flushSync(() =>
    root.render(
      <Modal
        key="long-title"
        title={`Правило ${"r".repeat(500)}`}
        onClose={() => {}}
      >
        <div className="form-stack">
          <p>
            Синтетическая проверка содержимого окна с длинным идентификатором
            правила.
          </p>
          <div style={{ minHeight: 600 }}>
            Прокручиваемое содержимое фикстуры
          </div>
          <div className="modal-footer">
            <button type="button" className="button button-secondary">
              Вернуться к настройке подключения
            </button>
            <button type="button" className="button button-primary">
              Сохранить выбранные параметры и продолжить
            </button>
          </div>
        </div>
      </Modal>,
    ),
  );
  const dialog = get<HTMLDialogElement>("dialog");
  const content = get(".modal-content");
  const header = get(".modal-header");
  const bounds = dialog.getBoundingClientRect();
  const close = get(".modal-header button").getBoundingClientRect();
  check(
    "long-title: native modal open",
    dialog.open && dialog.matches(":modal"),
  );
  check(
    "long-title: content has positive usable height",
    content.clientHeight >= 48,
    { height: content.clientHeight, headerHeight: header.clientHeight },
  );
  check(
    "long-title: dialog bounded in viewport",
    bounds.top >= 0 &&
      bounds.bottom <= innerHeight + 1 &&
      bounds.left >= 0 &&
      bounds.right <= innerWidth + 1,
    bounds.toJSON(),
  );
  check(
    "long-title: no horizontal overflow",
    document.documentElement.scrollWidth <= innerWidth + 1 &&
      content.scrollWidth <= content.clientWidth + 1 &&
      header.scrollWidth <= header.clientWidth + 1,
  );
  check(
    "long-title: close control visible",
    close.top >= bounds.top &&
      close.bottom <= bounds.bottom &&
      close.right <= bounds.right,
  );
  content.scrollTop = content.scrollHeight;
  check("long-title: content scrolls", content.scrollTop > 0);
  const actions = [
    ...document.querySelectorAll<HTMLElement>(".modal-footer button"),
  ];
  for (const [index, action] of actions.entries()) {
    const before = action.getBoundingClientRect();
    const port = content.getBoundingClientRect();
    content.scrollTop += before.top - port.top;
    const visible = action.getBoundingClientRect();
    check(
      `long-title: footer action ${index + 1} reachable`,
      visible.top >= port.top - 1 &&
        visible.bottom <= port.bottom + 1 &&
        visible.left >= bounds.left &&
        visible.right <= bounds.right,
      { action: visible.toJSON(), scrollport: port.toJSON() },
    );
  }
  snapshots.push({
    stage: "long-title",
    contentHeight: content.clientHeight,
    headerHeight: header.clientHeight,
    dialogHeight: bounds.height,
  });
}
// rAF uses real layout; the timeout is a bounded fallback for background headless frame throttling.
Promise.race([
  new Promise<void>((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
  ),
  new Promise<void>((resolve) => setTimeout(resolve, 100)),
]).then(async () => {
  try {
    await exercise("page");
    await exercise("modal");
    exerciseLongTitle();
  } catch (error) {
    check("fixture completed without exception", false, String(error));
  }
  parent.postMessage(
    {
      browserLayout: true,
      config,
      checks,
      snapshots,
      pass: checks.length > 0 && checks.every((item) => item.pass),
    },
    "*",
  );
});
