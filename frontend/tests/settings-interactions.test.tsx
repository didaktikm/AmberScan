import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  test,
} from "bun:test";
import { Window } from "happy-dom";
import { act, useState, type ReactNode } from "react";
import { setSession } from "../src/api";
import type { AdminSetup, Capabilities, Cluster, User } from "../src/types";

// Only this test file installs an in-process DOM; it never opens a real network connection.
const dom = new Window({ url: "https://workbench.example/" });
const savedGlobals = new Map<string, PropertyDescriptor | undefined>();
for (const key of [
  "window",
  "document",
  "navigator",
  "HTMLElement",
  "HTMLInputElement",
  "HTMLTextAreaElement",
  "HTMLSelectElement",
  "HTMLDialogElement",
  "Event",
  "MouseEvent",
  "IS_REACT_ACT_ENVIRONMENT",
]) {
  savedGlobals.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
  Object.defineProperty(globalThis, key, {
    configurable: true,
    writable: true,
    value:
      key === "IS_REACT_ACT_ENVIRONMENT"
        ? true
        : key === "window"
          ? dom
          : Reflect.get(dom, key),
  });
}
const { createRoot } = await import("react-dom/client");
const { SettingsPage } = await import("../src/pages/Settings");
const { ClusterWizard, ClusterDetail, ClustersPage } =
  await import("../src/pages/Clusters");
const { NamespacePicker } = await import("../src/NamespacePicker");
const { RunLaunch } = await import("../src/RunLaunch");
const { ScopeEditor } = await import("../src/ScopeEditor");
const { ModesPage } = await import("../src/pages/Overview");
const { useResource } = await import("../src/hooks");
const originalFetch = globalThis.fetch;
const admin: User = {
  id: "test-admin",
  username: "test-admin",
  role: "administrator",
};
const cluster: Cluster = {
  id: "test-cluster",
  lifecycle: "ready",
  access_revision: 1,
  name: "Test cluster",
  environment: "test",
  context: "test-context",
  server: "https://cluster.example",
  status: "authorized",
  created_at: "2026-01-01T00:00:00Z",
  credential_expires_at: "2099-01-01T00:00:00Z",
  auth_type: "kubeconfig",
  namespaces: ["test"],
  storage_mode: "run_only",
};
let setup: AdminSetup;
let calls: Array<{
  path: string;
  method: string;
  body: Record<string, unknown> | undefined;
  headers: Headers;
}>;
let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;
let handler: (
  path: string,
  method: string,
  body: Record<string, unknown> | undefined,
) => Response | Promise<Response>;
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
function defaultHandler(
  path: string,
  method: string,
  body: Record<string, unknown> | undefined,
): Response {
  if (path === "/api/admin/setup") return json(setup);
  if (path === "/api/admin/reauth")
    return json({
      reauthenticated_until: new Date(Date.now() + 300_000).toISOString(),
    });
  if (path === "/api/capabilities")
    return json({
      version: "test-only",
      features: [],
      limits: {},
    });
  if (path === "/api/admin/egress-policy" && method === "PUT") {
    setup = {
      ...setup,
      policy: {
        ...setup.policy,
        revision: setup.policy.revision + 1,
        rules: body?.rules as AdminSetup["policy"]["rules"],
      },
    };
    return json(setup.policy);
  }
  if (
    path === `/api/clusters/${cluster.id}/authorization` ||
    path === `/api/clusters/${cluster.id}/credential`
  )
    return json({ ok: true });
  throw new Error(`Unexpected test request ${method} ${path}`);
}
beforeEach(() => {
  setup = {
    policy: { revision: 0, rules: [], legacy_imported: false },
    reauthenticated_until: null,
    legacy_configuration_available: false,
  };
  calls = [];
  handler = defaultHandler;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input),
      method = init?.method ?? "GET",
      body = init?.body
        ? (JSON.parse(String(init.body)) as Record<string, unknown>)
        : undefined;
    calls.push({ path, method, body, headers: new Headers(init?.headers) });
    return handler(path, method, body);
  }) as typeof fetch;
  setSession({ user: admin, csrf_token: "test-csrf" });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  globalThis.fetch = originalFetch;
  setSession(null);
});
afterAll(() => {
  for (const [key, descriptor] of savedGlobals) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else Reflect.deleteProperty(globalThis, key);
  }
  void dom.happyDOM.abort();
});
async function mount(node: ReactNode) {
  await act(async () => {
    root.render(node);
  });
}
function button(text: string, within: ParentNode = lastDialog() ?? container) {
  const found = [...within.querySelectorAll<HTMLButtonElement>("button")].find(
    (element) => element.textContent?.trim() === text,
  );
  if (!found) throw new Error(`Missing test button: ${text}`);
  return found;
}
function field(text: string, within: ParentNode = lastDialog() ?? container) {
  const label = [...within.querySelectorAll("label")].find((element) =>
    element.textContent?.trim().startsWith(text),
  );
  const input = label?.querySelector<
    HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
  >("input,textarea,select");
  if (!input) throw new Error(`Missing test field: ${text}`);
  return input;
}
async function fill(text: string, value: string, within?: ParentNode) {
  const input = field(text, within);
  const prototype =
    input.tagName === "SELECT"
      ? HTMLSelectElement.prototype
      : input.tagName === "TEXTAREA"
        ? HTMLTextAreaElement.prototype
        : HTMLInputElement.prototype;
  await act(async () => {
    Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(
      input,
      value,
    );
    input.dispatchEvent(
      new Event(input.tagName === "SELECT" ? "change" : "input", {
        bubbles: true,
      }),
    );
  });
}
async function click(text: string, within?: ParentNode) {
  await act(async () => button(text, within).click());
}
async function submit(text: string) {
  const form = button(text).closest("form");
  if (!form) throw new Error(`Missing form for ${text}`);
  await act(async () =>
    form.dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    ),
  );
}
async function editPolicy() {
  await click("Изменить политику");
}
function lastDialog() {
  return [...container.querySelectorAll("dialog")].at(-1)!;
}

describe("B1 real frontend state, isolated API fixtures", () => {
  test("loaded settings expose egress only, never provider routes or controls", async () => {
    await mount(<SettingsPage user={admin} />);
    expect(container.textContent).toContain("Исходящие подключения");
    for (const removed of [
      "OIDC",
      "Callback",
      "Redirect URI",
      "Client secret",
      "Добавить провайдера",
      "Проверить сохранённую версию",
    ])
      expect(container.textContent).not.toContain(removed);
    await click("Изменить политику");
    await click("Добавить правило");
    expect(field("Назначение").value).toBe("kubernetes");
    expect(container.querySelector('option[value="oidc"]')).toBeNull();
    expect(calls.map((call) => call.path)).toEqual(["/api/admin/setup"]);
  });
  test("loading, API failure and empty egress policy are distinct", async () => {
    let complete!: (response: Response) => void;
    handler = () =>
      new Promise((resolve) => {
        complete = resolve;
      });
    await mount(<SettingsPage user={admin} />);
    expect(container.textContent).toContain("Загружаем настройки");
    expect(container.textContent).not.toContain(
      "Все внешние подключения будут запрещены",
    );
    await act(async () =>
      complete(
        json(
          {
            detail: { code: "unavailable", message: "Test setup unavailable" },
          },
          503,
        ),
      ),
    );
    expect(container.textContent).toContain("Test setup unavailable");
    expect(container.textContent).not.toContain(
      "Все внешние подключения будут запрещены",
    );
    handler = defaultHandler;
    await click("Повторить");
    expect(container.textContent).toContain(
      "Все внешние подключения будут запрещены",
    );
  });
  test("save requires preview plus password and clears password after save", async () => {
    await mount(<SettingsPage user={admin} />);
    await editPolicy();
    await click("Добавить правило");
    expect(field("Назначение").value).toBe("kubernetes");
    await fill("Идентификатор правила", "kube-api");
    await fill("Точный адрес узла", "cluster.example");
    await fill("Допустимые CIDR", "10.0.0.0/8");
    await submit("Просмотреть изменения");
    expect(calls.filter((call) => call.method !== "GET")).toHaveLength(0);
    expect(lastDialog().textContent).toContain(
      "отзовёт все личные учётные данные",
    );
    await fill("Пароль администратора", "TEST-ONLY-PASSWORD", lastDialog());
    await submit("Подтвердить и сохранить");
    const mutations = calls.filter((call) => call.method !== "GET");
    expect(mutations.map((call) => call.path)).toEqual([
      "/api/admin/reauth",
      "/api/admin/egress-policy",
    ]);
    expect(mutations[0].body).toEqual({ password: "TEST-ONLY-PASSWORD" });
    expect(mutations[1].body).toEqual({
      expected_revision: 0,
      rules: [
        {
          id: "kube-api",
          purpose: "kubernetes",
          host: "cluster.example",
          port: 443,
          cidrs: ["10.0.0.0/8"],
        },
      ],
    });
    expect(
      mutations.every(
        (call) => call.headers.get("X-CSRF-Token") === "test-csrf",
      ),
    ).toBe(true);
    expect(container.querySelectorAll('input[type="password"]')).toHaveLength(
      0,
    );
    expect(container.textContent).toContain(
      "Политика исходящих подключений сохранена",
    );
    expect(container.textContent).not.toContain("TEST-ONLY-PASSWORD");
    expect(dom.localStorage.length).toBe(0);
    expect(dom.sessionStorage.length).toBe(0);
  });
  test("wrong password blocks save, clears password and keeps preview for deliberate retry", async () => {
    handler = (path, method, body) =>
      path === "/api/admin/reauth"
        ? json(
            {
              detail: {
                code: "reauthentication_failed",
                message: "Password not confirmed",
              },
            },
            403,
          )
        : defaultHandler(path, method, body);
    await mount(<SettingsPage user={admin} />);
    await editPolicy();
    await submit("Просмотреть изменения");
    await fill("Пароль администратора", "TEST-WRONG", lastDialog());
    await submit("Подтвердить и сохранить");
    expect(lastDialog().textContent).toContain("Пароль не подтверждён");
    expect(field("Пароль администратора", lastDialog()).value).toBe("");
    expect(calls.some((call) => call.path === "/api/admin/egress-policy")).toBe(
      false,
    );
  });
  test("expired reauthentication response prompts again without silently replaying a mutation", async () => {
    setup.reauthenticated_until = new Date(Date.now() + 300_000).toISOString();
    handler = (path, method, body) =>
      path === "/api/admin/egress-policy"
        ? json(
            {
              detail: { code: "reauthentication_required", message: "Expired" },
            },
            403,
          )
        : defaultHandler(path, method, body);
    await mount(<SettingsPage user={admin} />);
    await editPolicy();
    await submit("Просмотреть изменения");
    await submit("Подтвердить и сохранить");
    expect(lastDialog().textContent).toContain("срок подтверждения истёк");
    expect(field("Пароль администратора", lastDialog()).value).toBe("");
    expect(
      calls.filter((call) => call.path === "/api/admin/egress-policy"),
    ).toHaveLength(1);
    expect(calls.some((call) => call.path === "/api/admin/reauth")).toBe(false);
  });
  test("revision conflict keeps the preview and directs a reload instead of claiming success", async () => {
    setup.reauthenticated_until = new Date(Date.now() + 300_000).toISOString();
    handler = (path, method, body) =>
      path === "/api/admin/egress-policy"
        ? json(
            { detail: { code: "conflict", message: "Changed concurrently" } },
            409,
          )
        : defaultHandler(path, method, body);
    await mount(<SettingsPage user={admin} />);
    await editPolicy();
    await submit("Просмотреть изменения");
    await submit("Подтвердить и сохранить");
    expect(lastDialog().textContent).toContain("обновите данные");
    expect(container.textContent).not.toContain(
      "Политика исходящих подключений сохранена",
    );
  });
  test("whole-policy replacement sends PUT with expected_revision and explicit empty-deny preview", async () => {
    setup.policy.revision = 4;
    setup.reauthenticated_until = new Date(Date.now() + 300_000).toISOString();
    await mount(<SettingsPage user={admin} />);
    await click("Изменить политику");
    await submit("Просмотреть изменения");
    expect(lastDialog().textContent).toContain(
      "Все внешние подключения будут запрещены",
    );
    await submit("Подтвердить и сохранить");
    const save = calls.find((call) => call.method === "PUT");
    expect(save?.path).toBe("/api/admin/egress-policy");
    expect(save?.body).toEqual({ expected_revision: 4, rules: [] });
    expect(calls.some((call) => call.path === "/api/admin/reauth")).toBe(false);
  });
  test("wizard retains inspected kubeconfig and metadata across Settings save/close, then creates only a draft", async () => {
    const kubeconfig = "TEST-ONLY-IN-MEMORY-KUBECONFIG";
    const created: Cluster[] = [];
    handler = (path, method, body) => {
      if (path === "/api/kubeconfig/inspect")
        return json({
          contexts: [
            {
              context: "test-context",
              cluster_name: "test-cluster",
              server: "https://cluster.example",
              username: "test",
              auth_type: "token",
              warnings: [],
            },
          ],
        });
      if (path === "/api/cluster-drafts" && method === "POST")
        return json(
          {
            ...cluster,
            lifecycle: "draft",
            namespaces: [],
            status: "authorization_required",
            credential_expires_at: null,
          },
          201,
        );
      return defaultHandler(path, method, body);
    };
    function WizardHarness() {
      const capabilities = useResource<Capabilities>("/capabilities");
      return (
        <ClusterWizard
          user={admin}
          capabilities={capabilities.data}
          capabilitiesLoading={capabilities.loading}
          capabilitiesError={capabilities.error}
          reloadCapabilities={capabilities.reload}
          onClose={() => {}}
          onCreated={(value) => created.push(value)}
        />
      );
    }
    await mount(<WizardHarness />);
    const fileInput =
      container.querySelector<HTMLInputElement>('input[type="file"]')!;
    Object.defineProperty(fileInput, "files", {
      configurable: true,
      value: [new File([kubeconfig], "config")],
    });
    await act(async () =>
      fileInput.dispatchEvent(new Event("change", { bubbles: true })),
    );
    await submit("Проверить файл");
    await act(async () =>
      container
        .querySelector<HTMLInputElement>('input[name="context"]')!
        .click(),
    );
    await submit("Продолжить");
    await fill("Название кластера", "Draft cluster name");
    await fill("Окружение", "test-env");
    expect(container.textContent).not.toContain("OIDC");
    const before = calls.filter(
      (call) => call.path === "/api/capabilities",
    ).length;
    await click("Настройки подключений");
    await editPolicy();
    await submit("Просмотреть изменения");
    // Cancelling only the innermost dialog must not close Settings or the wizard.
    await act(async () =>
      lastDialog().dispatchEvent(
        new Event("cancel", { bubbles: true, cancelable: true }),
      ),
    );
    expect(container.querySelectorAll("dialog")).toHaveLength(2);
    await submit("Просмотреть изменения");
    await fill("Пароль администратора", "TEST-PASSWORD", lastDialog());
    await submit("Подтвердить и сохранить");
    expect(
      calls.filter((call) => call.path === "/api/capabilities").length,
    ).toBeGreaterThan(before);
    await act(async () =>
      lastDialog()
        .querySelector<HTMLButtonElement>('button[aria-label="Закрыть окно"]')!
        .click(),
    );
    expect(container.querySelectorAll("dialog")).toHaveLength(1);
    expect(field("Название кластера").value).toBe("Draft cluster name");
    expect(field("Окружение").value).toBe("test-env");
    expect(
      calls.filter((call) => call.path === "/api/capabilities").length,
    ).toBeGreaterThan(before + 1);
    await submit("Создать черновик");
    expect(created).toHaveLength(0);
    expect(container.textContent).toContain(
      "Повторно импортировать kubeconfig",
    );
    expect(
      calls.find((call) => call.path === "/api/cluster-drafts")?.body,
    ).toEqual({
      connection: {
        kind: "kubeconfig",
        content: kubeconfig,
        context: "test-context",
      },
      name: "Draft cluster name",
      environment: "test-env",
      auth_type: "kubeconfig",
      storage_mode: "run_only",
      accept_alias: false,
    });
    expect(calls.some((call) => call.path === "/api/clusters")).toBe(false);
    expect(
      calls.filter((call) => call.path === "/api/kubeconfig/inspect"),
    ).toHaveLength(1);
    expect(dom.localStorage.length).toBe(0);
    expect(dom.sessionStorage.length).toBe(0);
  });
  test("auditor personal revoke uses own endpoint without administrator reauthentication", async () => {
    let changed = 0;
    await mount(
      <ClusterDetail
        cluster={cluster}
        user={{ ...admin, role: "auditor" }}
        onClose={() => {}}
        onChanged={() => {
          changed += 1;
        }}
        onLaunch={() => {}}
      />,
    );
    await click("Отозвать мою авторизацию");
    await click("Подтвердить личный отзыв");
    expect(calls.map((call) => [call.method, call.path])).toEqual([
      ["DELETE", `/api/clusters/${cluster.id}/authorization`],
    ]);
    expect(changed).toBe(1);
    expect(container.textContent).toContain(
      "Авторизации других пользователей не изменены",
    );
  });
  test("all-user revoke is separately protected and remains possible after personal revoke", async () => {
    await mount(
      <ClusterDetail
        cluster={cluster}
        user={admin}
        onClose={() => {}}
        onChanged={() => {}}
        onLaunch={() => {}}
      />,
    );
    await click("Отозвать мою авторизацию");
    await click("Подтвердить личный отзыв");
    await click("Отозвать авторизации всех пользователей");
    expect(calls.some((call) => call.path.endsWith("/credential"))).toBe(false);
    await fill("Пароль администратора", "TEST-PASSWORD", lastDialog());
    await submit("Отозвать все авторизации");
    expect(calls.slice(-2).map((call) => [call.method, call.path])).toEqual([
      ["POST", "/api/admin/reauth"],
      ["DELETE", `/api/clusters/${cluster.id}/credential`],
    ]);
  });
  test("Modes heading does not label unavailable features as available", async () => {
    handler = () =>
      json({
        version: "test",
        features: [
          {
            id: "cli",
            title: "CLI",
            status: "unavailable",
            detail: "Not implemented",
          },
        ],
        limits: {},
      });
    await mount(<ModesPage />);
    expect(container.textContent).toContain("Состояние функций в версии test");
    expect(container.textContent).not.toContain("Доступно в версии");
    expect(container.textContent).toContain("Недоступно");
    expect(container.textContent).not.toContain("Реализовано");
  });
  test("Modes splits the two implemented capabilities from the rest", async () => {
    handler = () =>
      json({
        version: "0.5.0",
        features: [
          {
            id: "read_only",
            title: "Разовый аудит только на чтение",
            status: "available",
            detail: "Встроенные проверки",
          },
          {
            id: "imports",
            title: "Импорт отчётов",
            status: "available",
            detail: "Готовые JSON",
          },
          {
            id: "scheduled",
            title: "Периодический аудит",
            status: "not_implemented",
            detail: "Не запускается",
          },
        ],
        limits: { list_rows: 500 },
      });
    await mount(<ModesPage />);
    const text = container.textContent ?? "";
    const done = text.indexOf("Доступно");
    const pending = text.indexOf("Не реализовано");
    expect(done).toBeGreaterThan(-1);
    expect(pending).toBeGreaterThan(done);
    expect(text.indexOf("Разовый аудит только на чтение")).toBeLessThan(pending);
    expect(text.indexOf("Импорт отчётов")).toBeLessThan(pending);
    expect(text.indexOf("Периодический аудит")).toBeGreaterThan(pending);
  });
});

const allowedCoverage = [
  {
    check: "test/pods",
    namespace: "test",
    resource: "pods",
    group: "",
    verb: "list",
    status: "completed",
    code: "allowed",
    detail: "TEST allowed",
  },
];
const partialCoverage = [
  ...allowedCoverage,
  {
    check: "test/services",
    namespace: "test",
    resource: "services",
    group: "",
    verb: "list",
    status: "denied",
    code: "http_403",
    detail: "TEST RBAC denied",
  },
];
const draft = {
  ...cluster,
  id: "12345678-1234-1234-abcd-123456789abc",
  lifecycle: "draft" as const,
  namespaces: [],
  namespace_hint: "hint-only",
  draft_expires_at: "2099-01-02T00:00:00Z",
};
const capabilities: Capabilities = {
  version: "0.3.0",
  features: [],
  limits: {},
};
async function checkNamespace(name: string) {
  const input = container.querySelector<HTMLInputElement>(
    `input[aria-label="Пространство имён ${name}"]`,
  );
  if (!input) throw new Error(`Missing namespace ${name}`);
  await act(async () => input.click());
}
function wizardForDraft(
  onCreated: (value: Cluster) => void = () => {},
  onClose = () => {},
) {
  return (
    <ClusterWizard
      user={admin}
      capabilities={capabilities}
      capabilitiesLoading={false}
      reloadCapabilities={() => {}}
      resumeId={draft.id}
      onClose={onClose}
      onCreated={onCreated}
    />
  );
}

describe("namespace picker with the existing happy-dom harness", () => {
  function PickerHarness({
    options = ["alpha", "beta", "kube-system"],
    initial = [],
  }: {
    options?: string[];
    initial?: string[];
  }) {
    const [selected, setSelected] = useState(initial);
    return (
      <NamespacePicker
        selected={selected}
        onChange={setSelected}
        options={options.map((name) => ({ name, system: false }))}
        hint="beta"
      />
    );
  }
  test("empty default, context hint, system badges, search preserves hidden choice and explicit all/filtered/clear", async () => {
    await mount(<PickerHarness />);
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(0);
    expect(container.textContent).toContain("Выбрано 0 из 100");
    expect(container.textContent).toContain(
      "Пространство имён из контекста: beta",
    );
    expect(container.textContent).toContain("Системное");
    await checkNamespace("alpha");
    await fill("Поиск пространства имён", "beta");
    expect(container.textContent).toContain("Выбрано вне фильтра: 1");
    await click("Выбрать по фильтру (1)", container);
    expect(container.textContent).toContain("Выбрано 2 из 100");
    await click("Выбрать все загруженные (3)", container);
    expect(container.textContent).toContain("Выбрано 3 из 100");
    await click("Снять выделение", container);
    expect(container.textContent).toContain("Выбрано 0 из 100");
  });
  test("refresh keeps missing names selected, never selects new ones, manual names stay unverified", async () => {
    await mount(<PickerHarness />);
    await checkNamespace("alpha");
    await mount(<PickerHarness options={["beta", "new"]} />);
    expect(container.textContent).toContain("Не найдено в обновлённом списке");
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён alpha"]',
      )?.checked,
    ).toBe(true);
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён new"]',
      )?.checked,
    ).toBe(false);
    await fill("Имена через запятую", "manual-name");
    await click("Добавить к выбору", container);
    expect(container.textContent).toContain("Введено вручную");
    expect(container.textContent).toContain("существование не подтверждено");
    expect(container.textContent).toContain("Выбрано 2 из 100");
  });
  test("101-name bulk action fails without silently selecting 100", async () => {
    await mount(
      <PickerHarness
        options={Array.from({ length: 101 }, (_, index) => `ns-${index}`)}
      />,
    );
    await click("Выбрать все загруженные (101)", container);
    expect(container.textContent).toContain("не более 100");
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(0);
  });
  test("manual additions at limit preserve the existing 100 choices", async () => {
    await mount(
      <PickerHarness
        initial={Array.from({ length: 100 }, (_, index) => `ns-${index}`)}
      />,
    );
    await fill("Имена через запятую", "another");
    await click("Добавить к выбору", container);
    expect(container.textContent).toContain("не более 100");
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(100);
  });
});

describe("selected-only run and preflight", () => {
  test("run starts empty, requires selected-only preflight, submits only chosen subset", async () => {
    const created: unknown[] = [];
    handler = (path) =>
      path.endsWith("/preflight")
        ? json({ coverage: allowedCoverage })
        : path === "/api/runs"
          ? json({ id: "new-run" }, 201)
          : json({});
    await mount(
      <RunLaunch
        clusters={[{ ...cluster, namespaces: ["test", "other"] }]}
        initialCluster={cluster.id}
        onClose={() => {}}
        onCreated={(run) => created.push(run)}
      />,
    );
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(0);
    expect(button("Запустить проверку").disabled).toBe(true);
    await checkNamespace("test");
    expect(button("Запустить проверку").disabled).toBe(true);
    await click("Проверить выбранные пространства имён");
    expect(calls.at(-1)?.body).toEqual({ namespaces: ["test"] });
    expect(button("Запустить проверку").disabled).toBe(false);
    await submit("Запустить проверку");
    expect(calls.at(-1)?.body).toEqual({
      cluster_id: cluster.id,
      namespaces: ["test"],
      timeout_seconds: 300,
    });
    expect(created).toHaveLength(1);
    expect(container.textContent).toContain(
      "Кластерные проверки не поддерживаются и не включены",
    );
  });
  test("run rejects manual out-of-allowlist names and never enables drafts", async () => {
    await mount(
      <RunLaunch
        clusters={[cluster, draft]}
        initialCluster={cluster.id}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    expect(container.querySelector(`option[value="${draft.id}"]`)).toBeNull();
    await fill("Имена через запятую", "outside");
    await click("Добавить к выбору");
    expect(container.textContent).toContain("подмножеством");
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });
  test("partial coverage needs explicit acknowledgment, scope change invalidates both", async () => {
    handler = () => json({ coverage: partialCoverage });
    await mount(
      <RunLaunch
        clusters={[{ ...cluster, namespaces: ["test", "other"] }]}
        initialCluster={cluster.id}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    await checkNamespace("test");
    await click("Проверить выбранные пространства имён");
    expect(button("Запустить проверку").disabled).toBe(true);
    await act(async () =>
      (field("Принимаю частичное покрытие") as HTMLInputElement).click(),
    );
    expect(button("Запустить проверку").disabled).toBe(false);
    await checkNamespace("other");
    expect(container.textContent).not.toContain("TEST RBAC denied");
    expect(container.textContent).not.toContain("Принимаю частичное");
    expect(button("Запустить проверку").disabled).toBe(true);
  });
  test("late preflight cannot restore coverage after selection changes", async () => {
    let complete!: (response: Response) => void;
    handler = () =>
      new Promise((resolve) => {
        complete = resolve;
      });
    await mount(
      <RunLaunch
        clusters={[{ ...cluster, namespaces: ["test", "other"] }]}
        initialCluster={cluster.id}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    await checkNamespace("test");
    await click("Проверить выбранные пространства имён");
    await checkNamespace("other");
    await act(async () => complete(json({ coverage: allowedCoverage })));
    expect(container.textContent).not.toContain("TEST allowed");
    expect(button("Запустить проверку").disabled).toBe(true);
  });
  test("new cluster metadata by id revokes stale coverage and retains disallowed selection visibly", async () => {
    handler = () => json({ coverage: allowedCoverage });
    const render = (value: Cluster) => (
      <RunLaunch
        clusters={[value]}
        initialCluster={cluster.id}
        onClose={() => {}}
        onCreated={() => {}}
      />
    );
    await mount(render(cluster));
    await checkNamespace("test");
    await click("Проверить выбранные пространства имён");
    expect(button("Запустить проверку").disabled).toBe(false);
    await mount(
      render({ ...cluster, access_revision: 2, namespaces: ["new"] }),
    );
    expect(button("Запустить проверку").disabled).toBe(true);
    expect(container.textContent).toContain("Больше не разрешено");
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён new"]',
      )?.checked,
    ).toBe(false);
    await click("Проверить выбранные пространства имён");
    expect(calls).toHaveLength(1);
    expect(container.textContent).toContain("подмножеством");
  });
  test("cluster detail preflight also starts empty", async () => {
    await mount(
      <ClusterDetail
        cluster={cluster}
        user={admin}
        onClose={() => {}}
        onChanged={() => {}}
        onLaunch={() => {}}
      />,
    );
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(0);
    expect(button("Проверить доступ").disabled).toBe(true);
  });
});

describe("draft connection lifecycle", () => {
  test("authorized draft resume discovers automatically with empty selection and selected preflight finalizes via CAS", async () => {
    const created: Cluster[] = [];
    handler = (path) =>
      path === `/api/cluster-drafts/${draft.id}`
        ? json(draft)
        : path.endsWith("/namespaces/discover")
          ? json({
              status: "complete",
              items: [
                { name: "test", system: false },
                { name: "other", system: false },
              ],
              complete: true,
              limitation: null,
            })
          : path.endsWith("/preflight")
            ? json({ coverage: allowedCoverage })
            : path.endsWith("/finalize")
              ? json({ cluster, coverage: allowedCoverage })
              : json({});
    await mount(wizardForDraft((value) => created.push(value)));
    expect(calls).toHaveLength(2);
    expect(container.textContent).toContain("Выбрано 0 из 100");
    expect(container.textContent).toContain(
      "Повторно импортировать kubeconfig",
    );
    await click("Обновить список");
    expect(calls.at(-1)?.body).toEqual({});
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(0);
    await checkNamespace("test");
    await click("Проверить выбранные пространства имён");
    expect(calls.at(-1)?.body).toEqual({ namespaces: ["test"] });
    await click("Сохранить подключение");
    expect(calls.at(-1)?.path).toBe(`/api/cluster-drafts/${draft.id}/finalize`);
    expect(calls.at(-1)?.body).toEqual({
      namespaces: ["test"],
      expected_access_revision: 1,
      accept_partial: false,
    });
    expect(created).toHaveLength(1);
    expect(dom.localStorage.length).toBe(0);
    expect(dom.sessionStorage.length).toBe(0);
  });
  test("forbidden discovery supports unverified manual selection, not false empty", async () => {
    handler = (path) =>
      path.endsWith("/namespaces/discover")
        ? json({
            status: "forbidden",
            items: [],
            complete: false,
            limitation: "Denied",
          })
        : json(draft);
    await mount(wizardForDraft());
    await click("Обновить список");
    expect(container.textContent).toContain(
      "Это не означает, что кластер пуст",
    );
    expect(container.textContent).not.toContain("Получен пустой список");
    await fill("Имена через запятую", "known");
    await click("Добавить к выбору");
    expect(container.textContent).toContain("Введено вручную");
    expect(container.textContent).toContain("Выбрано 1 из 100");
  });
  test.each(["http_tls", "http_network", "kubernetes_authentication_required"])(
    "%s discovery error is not forbidden or successful-empty",
    async (code) => {
      handler = (path) =>
        path.endsWith("/namespaces/discover")
          ? json({ detail: { code, message: "TEST fatal discovery" } }, 409)
          : json(draft);
      await mount(wizardForDraft());
      await click("Обновить список");
      expect(container.textContent).toContain(
        code === "http_tls"
          ? "Не удалось установить TLS-соединение или проверить сертификат сервера."
          : code === "kubernetes_authentication_required"
            ? "Kubernetes отклонил учётные данные. Повторно импортируйте kubeconfig для этого подключения."
            : "TEST fatal discovery",
      );
      expect(container.textContent).not.toContain("Получен пустой список");
      expect(container.textContent).not.toContain(
        "Kubernetes запретил получение списка пространств имён",
      );
      expect(button("Сохранить подключение").disabled).toBe(true);
    },
  );
  test("failed refresh keeps prior options visibly stale, incomplete results do not claim absence", async () => {
    let phase = 0;
    handler = (path) =>
      !path.endsWith("/namespaces/discover")
        ? json(draft)
        : phase === 0
          ? json({
              status: "complete",
              items: [{ name: "test", system: false }],
              complete: true,
              limitation: null,
            })
          : phase === 1
            ? json(
                {
                  detail: {
                    code: "http_transport",
                    message: "TEST transport failed",
                  },
                },
                409,
              )
            : json({
                status: "partial",
                items: [],
                complete: false,
                limitation: "TEST incomplete",
              });
    await mount(wizardForDraft());
    await click("Обновить список");
    await checkNamespace("test");
    phase = 1;
    await click("Обновить список");
    expect(container.textContent).toContain("Показан предыдущий список");
    expect(container.textContent).toContain("Список и доступ не подтверждены");
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён test"]',
      )?.checked,
    ).toBe(true);
    phase = 2;
    await click("Обновить список");
    expect(container.textContent).toContain(
      "Не подтверждено текущим неполным списком",
    );
    expect(container.textContent).not.toContain(
      "Не найдено в обновлённом списке",
    );
    expect(container.textContent).not.toContain("Показан предыдущий список");
  });
  test("auth metadata change clears old discovery without changing selected names", async () => {
    let revised = false;
    handler = (path) =>
      path.endsWith("/namespaces/discover")
        ? json({
            status: "complete",
            items: [{ name: "test", system: false }],
            complete: true,
            limitation: null,
          })
        : json({
            ...draft,
            credential_expires_at: revised
              ? "2099-02-01T00:00:00Z"
              : draft.credential_expires_at,
          });
    await mount(wizardForDraft());
    await click("Обновить список");
    await checkNamespace("test");
    revised = true;
    await click("Повторно импортировать kubeconfig");
    await uploadKubeconfig("Повторный файл kubeconfig");
    await click("Заменить личные учётные данные");
    expect(calls.at(-1)?.path).toEndWith("/namespaces/discover");
    expect(container.textContent).not.toContain(
      "Список пространств имён ещё не получен",
    );
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён test"]',
      )?.checked,
    ).toBe(true);
  });
  test("partial finalize acknowledgment is explicit and server rejection invalidates it", async () => {
    handler = (path) =>
      path.endsWith("/preflight")
        ? json({ coverage: partialCoverage })
        : path.endsWith("/finalize")
          ? json(
              {
                detail: {
                  code: "preflight_failed",
                  message: "TEST access changed",
                },
              },
              409,
            )
          : json(draft);
    await mount(wizardForDraft());
    await fill("Имена через запятую", "test");
    await click("Добавить к выбору");
    await click("Проверить выбранные пространства имён");
    expect(button("Сохранить подключение").disabled).toBe(true);
    await act(async () =>
      (field("Принимаю частичное покрытие") as HTMLInputElement).click(),
    );
    await click("Сохранить подключение");
    expect(calls.at(-1)?.body?.accept_partial).toBe(true);
    expect(container.textContent).toContain(
      "Проверка доступа не подтвердила выбранную область.",
    );
    expect(button("Сохранить подключение").disabled).toBe(true);
    expect(container.textContent).not.toContain("Принимаю частичное покрытие");
  });
  test("closing draft keeps it resumable; explicit abort requires separate confirmation", async () => {
    let closed = 0;
    handler = (_path, method) =>
      method === "DELETE" ? new Response(null, { status: 204 }) : json(draft);
    await mount(
      wizardForDraft(
        () => {},
        () => {
          closed += 1;
        },
      ),
    );
    await click("Закрыть, продолжить позже");
    expect(closed).toBe(1);
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    await click("Отменить подключение");
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    await click("Подтвердить удаление черновика");
    expect(calls.at(-1)?.path).toBe(`/api/cluster-drafts/${draft.id}`);
    expect(calls.at(-1)?.method).toBe("DELETE");
    expect(closed).toBe(2);
  });
  test("draft list resumes only selected own id and fresh ready detail resolves by id", async () => {
    let revision = 1;
    handler = (path) =>
      path === "/api/cluster-drafts"
        ? json([draft])
        : path === `/api/cluster-drafts/${draft.id}`
          ? json(draft)
          : path === "/api/clusters"
            ? json([
                {
                  ...cluster,
                  name: revision === 1 ? "Original cluster" : "Updated cluster",
                  access_revision: revision,
                  namespaces: revision === 1 ? ["test"] : ["new"],
                },
              ])
            : json(capabilities);
    await mount(<ClustersPage user={admin} openRun={() => {}} />);
    await click(`Продолжить подключение ${draft.name}`, container);
    expect(
      calls.some((call) => call.path === `/api/cluster-drafts/${draft.id}`),
    ).toBe(true);
    await click("Закрыть, продолжить позже");
    await click("Original clustertest", container);
    expect(lastDialog().textContent).toContain("Original cluster");
    revision = 2;
    await click("Обновить", container);
    expect(lastDialog().textContent).toContain("Updated cluster");
    expect(
      container.querySelector('input[aria-label="Пространство имён new"]'),
    ).not.toBeNull();
  });
});

describe("cluster list actions", () => {
  test("add, edit and delete sit above the cluster list", async () => {
    let clusters = [cluster];
    handler = (path, method, body) => {
      if (path === "/api/clusters" && method === "GET") return json(clusters);
      if (path === "/api/cluster-drafts") return json([]);
      if (path === "/api/capabilities") return json(capabilities);
      if (path === `/api/clusters/${cluster.id}` && method === "PATCH") {
        clusters = [{ ...cluster, name: String(body?.name), environment: String(body?.environment) }];
        return json(clusters[0]);
      }
      if (path === `/api/clusters/${cluster.id}` && method === "DELETE") {
        clusters = [];
        return json({ status: "deleted" });
      }
      return defaultHandler(path, method, body);
    };
    await mount(<ClustersPage user={admin} openRun={() => {}} />);
    const actions = () =>
      container.querySelector<HTMLElement>('[aria-label="Действия с кластерами"]')!;
    expect(actions().textContent).toContain("Добавить");
    expect(actions().textContent).toContain("Изменить");
    expect(actions().textContent).toContain("Удалить");
    expect(button("Изменить", actions()).disabled).toBe(true);
    expect(button("Удалить", actions()).disabled).toBe(true);
    const box = container.querySelector<HTMLInputElement>(
      'input[aria-label="Выбрать кластер Test cluster"]',
    )!;
    await act(async () => box.click());
    expect(button("Изменить", actions()).disabled).toBe(false);
    await click("Изменить", actions());
    await fill("Название", "Переименованный");
    await fill("Окружение", "staging");
    await submit("Сохранить изменения");
    const renamed = calls.find((call) => call.method === "PATCH");
    expect(renamed?.body).toEqual({
      name: "Переименованный",
      environment: "staging",
    });
    await click("Удалить", actions());
    await fill("Пароль администратора", "TEST-PASSWORD");
    await submit("Удалить из приложения");
    const removed = calls.find((call) => call.method === "DELETE");
    expect(removed?.path).toBe(`/api/clusters/${cluster.id}`);
  });
});

describe("ready scope edit", () => {
  test("saved selection is explicit; admin reauth precedes candidate preflight and PATCH uses base CAS", async () => {
    const saved: Cluster[] = [];
    handler = (path, method, body) =>
      path.endsWith("/scope/preflight")
        ? json({ coverage: allowedCoverage })
        : path.endsWith("/scope")
          ? json({
              cluster: { ...cluster, access_revision: 2 },
              coverage: allowedCoverage,
            })
          : defaultHandler(path, method, body);
    await mount(
      <ScopeEditor
        cluster={cluster}
        onClose={() => {}}
        onChanged={(value) => saved.push(value)}
      />,
    );
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён test"]',
      )?.checked,
    ).toBe(true);
    await click("Проверить новую область");
    expect(calls).toHaveLength(0);
    await fill("Пароль администратора", "TEST-PASSWORD");
    await submit("Подтвердить и проверить область");
    expect(calls.map((call) => call.path)).toEqual([
      "/api/admin/reauth",
      `/api/clusters/${cluster.id}/scope/preflight`,
    ]);
    expect(calls.at(-1)?.body).toEqual({ namespaces: ["test"] });
    await click("Сохранить новую область");
    await submit("Подтвердить и сохранить область");
    expect(calls.at(-1)?.method).toBe("PATCH");
    expect(calls.at(-1)?.body).toEqual({
      namespaces: ["test"],
      expected_access_revision: 1,
      accept_partial: false,
    });
    expect(saved).toHaveLength(1);
  });
  test("revision changed while editing blocks overwriting fresh scope", async () => {
    const render = (value: Cluster) => (
      <ScopeEditor cluster={value} onClose={() => {}} onChanged={() => {}} />
    );
    await mount(render(cluster));
    await mount(
      render({ ...cluster, access_revision: 2, namespaces: ["new"] }),
    );
    expect(container.textContent).toContain(
      "Подключение изменилось в другой операции",
    );
    expect(button("Проверить новую область").disabled).toBe(true);
    expect(button("Сохранить новую область").disabled).toBe(true);
    expect(calls).toHaveLength(0);
  });
});

async function uploadKubeconfig(
  label = "Файл kubeconfig",
  content = "TEST-ONLY-INLINE-CREDENTIALS",
) {
  const input = container.querySelector<HTMLInputElement>(
    'input[aria-label="' + label + '"]',
  )!;
  Object.defineProperty(input, "files", {
    configurable: true,
    value: [new File([content], "config")],
  });
  await act(async () =>
    input.dispatchEvent(new Event("change", { bubbles: true })),
  );
  expect(input.value).toBe("");
}
const kubeCapabilities: Capabilities = {
  ...capabilities,
  version: "0.5.0",
  setup_required: false,
  kubernetes_setup_required: false,
};
const kubeDraft: Cluster = {
  ...draft,
  auth_type: "kubeconfig",
  credential_kind: "token",
};
const kubeReady: Cluster = {
  ...cluster,
  auth_type: "kubeconfig",
  credential_kind: "token",
};
const completeDiscovery = {
  status: "complete",
  complete: true,
  items: [
    { name: "test", system: false },
    { name: "kube-system", system: true },
  ],
  limitation: null,
  continuation: null,
};

describe("0.5 kubeCapabilities kubeconfig and personal recovery", () => {
  test.each(["token", "client_certificate"])(
    "%s imports directly to unselected discovery and selected-only finalize",
    async (kind) => {
      const created: Cluster[] = [];
      handler = (path) => {
        if (path.endsWith("/inspect"))
          return json({
            contexts: [
              {
                context: draft.context,
                cluster_name: "test",
                server: draft.server,
                username: "test",
                auth_type: kind,
                warnings: [],
                namespace_hint: "test",
              },
            ],
          });
        if (path === "/api/cluster-drafts")
          return json({ ...kubeDraft, credential_kind: kind }, 201);
        if (path.endsWith("/namespaces/discover"))
          return json(completeDiscovery);
        if (path.endsWith("/preflight"))
          return json({ coverage: allowedCoverage });
        if (path.endsWith("/finalize"))
          return json({ cluster: kubeReady, coverage: allowedCoverage });
        throw new Error("Unexpected kubeconfig request " + path);
      };
      await mount(
        <ClusterWizard
          user={admin}
          capabilities={kubeCapabilities}
          capabilitiesLoading={false}
          reloadCapabilities={() => {}}
          onClose={() => {}}
          onCreated={(value) => created.push(value)}
        />,
      );
      await uploadKubeconfig();
      await submit("Проверить файл");
      await act(async () =>
        container
          .querySelector<HTMLInputElement>('input[name="context"]')!
          .click(),
      );
      await submit("Продолжить");
      expect(container.textContent).not.toContain("Способ авторизации");
      expect(container.textContent).not.toContain(
        "Нет включённых OIDC-провайдеров",
      );
      expect(container.querySelector("select[required]")).toBeNull();
      expect(container.textContent).toContain("1 часа");
      expect(container.textContent).toContain("24 часов");
      expect(container.textContent).toContain(
        kind === "token" ? "встроенный токен" : "клиентский сертификат и ключ",
      );
      if (kind === "client_certificate")
        await act(async () =>
          container
            .querySelector<HTMLInputElement>('input[value="persistent"]')!
            .click(),
        );
      await fill("Название кластера", "Providerless");
      await fill("Окружение", "test");
      expect(button("Создать черновик").disabled).toBe(false);
      await submit("Создать черновик");
      expect(
        calls.find((call) => call.path === "/api/cluster-drafts")?.body,
      ).toEqual({
        name: "Providerless",
        environment: "test",
        auth_type: "kubeconfig",
        storage_mode: kind === "token" ? "run_only" : "persistent",
        accept_alias: false,
        connection: {
          kind: "kubeconfig",
          context: draft.context,
          content: "TEST-ONLY-INLINE-CREDENTIALS",
        },
      });
      expect(container.textContent).not.toContain(
        "TEST-ONLY-INLINE-CREDENTIALS",
      );
      expect(container.querySelector('input[type="file"]')).toBeNull();
      expect(
        container.querySelectorAll('input[type="checkbox"]:checked'),
      ).toHaveLength(0);
      expect(
        container.querySelector(
          'input[aria-label="Пространство имён kube-system"]',
        ),
      ).not.toBeNull();
      await checkNamespace("test");
      await click("Проверить выбранные пространства имён");
      expect(calls.at(-1)?.body).toEqual({ namespaces: ["test"] });
      await click("Сохранить подключение");
      expect(created).toHaveLength(1);
      expect(calls.some((call) => call.path.endsWith("/authorize"))).toBe(
        false,
      );
      expect(dom.localStorage.length).toBe(0);
      expect(dom.sessionStorage.length).toBe(0);
    },
  );

  test.each(["exec", "auth-provider", "unsupported", "none"])(
    "unsupported %s context is rejected without alternate login",
    async (kind) => {
      handler = () =>
        json({
          contexts: [
            {
              context: draft.context,
              cluster_name: "test",
              server: draft.server,
              username: "test",
              auth_type: kind,
              warnings: [],
            },
          ],
        });
      await mount(
        <ClusterWizard
          user={admin}
          capabilities={kubeCapabilities}
          capabilitiesLoading={false}
          reloadCapabilities={() => {}}
          onClose={() => {}}
          onCreated={() => {}}
        />,
      );
      expect(container.textContent).not.toContain("Источник метаданных");
      expect(container.querySelector('option[value="manual"]')).toBeNull();
      await uploadKubeconfig();
      await submit("Проверить файл");
      await act(async () =>
        container
          .querySelector<HTMLInputElement>('input[name="context"]')!
          .click(),
      );
      await submit("Продолжить");
      expect(container.textContent).toContain("Неподдерживаемый контекст");
      expect(container.textContent).not.toContain("OIDC");
      expect(container.textContent).not.toContain("Способ авторизации");
      expect(container.textContent).not.toContain("Создать черновик");
      expect(calls.map((call) => call.path)).toEqual([
        "/api/kubeconfig/inspect",
      ]);
    },
  );

  test("1000-name batch appends continuation without auto-selection or the selection cap hiding rows", async () => {
    handler = (path, _method, body) =>
      path.endsWith("/namespaces/discover")
        ? json(
            body?.continuation
              ? completeDiscovery
              : {
                  status: "partial",
                  complete: false,
                  items: Array.from({ length: 1000 }, (_, i) => ({
                    name: "team-" + i,
                    system: false,
                  })),
                  continuation: "OPAQUE-TEST-CURSOR",
                  limitation: "Batch limit",
                },
          )
        : json(kubeDraft);
    await mount(wizardForDraft());
    expect(container.textContent).toContain("Загружено 1000");
    expect(container.textContent).toContain("неполный список");
    await checkNamespace("team-0");
    await click("Загрузить ещё пространства имён");
    expect(calls.at(-1)?.body).toEqual({ continuation: "OPAQUE-TEST-CURSOR" });
    expect(container.textContent).toContain("Загружено 1002");
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(1);
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён kube-system"]',
      )?.checked,
    ).toBe(false);
    expect(container.textContent).not.toContain("неполный список");
    await click("Выбрать все загруженные (1002)");
    expect(
      container.querySelectorAll('input[type="checkbox"]:checked'),
    ).toHaveLength(1);
    expect(container.textContent).toContain("100");
  });

  test("expired continuation requires replacing snapshot and preserves explicit selection", async () => {
    let refresh = false;
    handler = (path, _method, body) => {
      if (!path.endsWith("/namespaces/discover")) return json(kubeDraft);
      if (body?.continuation) {
        refresh = true;
        return json(
          {
            detail: {
              code: "namespace_snapshot_expired",
              message: "TEST expired snapshot",
            },
          },
          400,
        );
      }
      return json(
        refresh
          ? completeDiscovery
          : {
              status: "partial",
              complete: false,
              items: [{ name: "old", system: false }],
              continuation: "OLD",
              limitation: null,
            },
      );
    };
    await mount(wizardForDraft());
    await checkNamespace("old");
    await click("Загрузить ещё пространства имён");
    expect(container.textContent).toContain("Снимок списка истёк");
    expect(container.textContent).not.toContain(
      "Загрузить ещё пространства имён",
    );
    await click("Обновить список");
    expect(calls.at(-1)?.body).toEqual({});
    expect(container.textContent).toContain("Загружено 2");
    expect(
      container.querySelector<HTMLInputElement>(
        'input[aria-label="Пространство имён old"]',
      )?.checked,
    ).toBe(true);
  });

  test.each(["draft", "detail", "run", "scope"])(
    "%s recovery reimports personal credentials with CAS and no authorize",
    async (surface) => {
      const expired = {
        ...(surface === "draft" ? kubeDraft : kubeReady),
        status: "authorization_required",
        credential_expires_at: null,
      };
      handler = (path, method) => {
        if (path.endsWith("/credential") && method === "POST")
          return json({
            ...expired,
            status: "authorized",
            credential_expires_at: "2099-02-01T00:00:00Z",
          });
        if (path.endsWith("/namespaces/discover"))
          return json(completeDiscovery);
        return json(expired);
      };
      await mount(
        surface === "draft" ? (
          wizardForDraft()
        ) : surface === "detail" ? (
          <ClusterDetail
            cluster={expired}
            user={admin}
            onClose={() => {}}
            onChanged={() => {}}
            onLaunch={() => {}}
          />
        ) : surface === "run" ? (
          <RunLaunch
            clusters={[expired]}
            initialCluster={expired.id}
            onClose={() => {}}
            onCreated={() => {}}
          />
        ) : (
          <ScopeEditor
            cluster={expired}
            onClose={() => {}}
            onChanged={() => {}}
          />
        ),
      );
      expect(container.textContent).not.toContain("Повторите OIDC");
      await click("Повторно импортировать kubeconfig");
      expect(
        container.querySelector<HTMLInputElement>('input[value="run_only"]')
          ?.checked,
      ).toBe(true);
      await uploadKubeconfig("Повторный файл kubeconfig");
      await click("Отмена импорта");
      await click("Повторно импортировать kubeconfig");
      expect(button("Заменить личные учётные данные").disabled).toBe(true);
      await uploadKubeconfig("Повторный файл kubeconfig");
      if (surface === "scope")
        await act(async () =>
          lastDialog()
            .querySelector<HTMLInputElement>('input[value="persistent"]')!
            .click(),
        );
      await click("Заменить личные учётные данные");
      expect(
        calls.find((call) => call.path.endsWith("/credential"))?.body,
      ).toEqual({
        content: "TEST-ONLY-INLINE-CREDENTIALS",
        context: expired.context,
        storage_mode: surface === "scope" ? "persistent" : "run_only",
        expected_access_revision: expired.access_revision,
      });
      expect(calls.some((call) => call.path.endsWith("/authorize"))).toBe(
        false,
      );
      expect(container.textContent).not.toContain(
        "TEST-ONLY-INLINE-CREDENTIALS",
      );
      await click("Повторно импортировать kubeconfig");
      expect(button("Заменить личные учётные данные").disabled).toBe(true);
      expect(
        lastDialog().querySelector<HTMLInputElement>('input[value="run_only"]')
          ?.checked,
      ).toBe(true);
    },
  );

  test("late recovery response cannot replace a changed cluster snapshot", async () => {
    let complete!: (value: Response) => void;
    handler = () =>
      new Promise((resolve) => {
        complete = resolve;
      });
    const source = {
      ...kubeReady,
      status: "authorization_required",
      credential_expires_at: null,
    };
    const render = (value: Cluster) => (
      <RunLaunch
        clusters={[value]}
        initialCluster={value.id}
        onClose={() => {}}
        onCreated={() => {}}
      />
    );
    await mount(render(source));
    await click("Повторно импортировать kubeconfig");
    await uploadKubeconfig("Повторный файл kubeconfig");
    await click("Заменить личные учётные данные");
    await mount(render({ ...source, access_revision: 2, namespaces: ["new"] }));
    await act(async () => complete(json(kubeReady)));
    expect(container.textContent).toContain(
      "Нет действующей личной авторизации",
    );
    expect(
      container.querySelector('input[aria-label="Пространство имён new"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('input[aria-label="Пространство имён test"]'),
    ).toBeNull();
  });
});

describe("0.5 recovery error and continuation fences", () => {
  test("rejected reimport preserves expired state and can be retried without OIDC", async () => {
    let reject = true;
    const expired: Cluster = {
      ...kubeReady,
      status: "authorization_required",
      credential_expires_at: null,
    };
    handler = () =>
      reject
        ? json(
            {
              detail: {
                code: "credential_connection_mismatch",
                message: "TEST immutable endpoint mismatch",
              },
            },
            409,
          )
        : json(kubeReady);
    await mount(
      <RunLaunch
        clusters={[expired]}
        initialCluster={expired.id}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    await click("Повторно импортировать kubeconfig");
    await uploadKubeconfig("Повторный файл kubeconfig");
    await click("Заменить личные учётные данные");
    expect(container.textContent).toContain("TEST immutable endpoint mismatch");
    expect(container.textContent).toContain(
      "Нет действующей личной авторизации",
    );
    expect(button("Заменить личные учётные данные").disabled).toBe(false);
    reject = false;
    await click("Заменить личные учётные данные");
    expect(container.textContent).not.toContain(
      "Нет действующей личной авторизации",
    );
    expect(calls).toHaveLength(2);
    expect(calls.every((call) => call.path.endsWith("/credential"))).toBe(true);
  });

  test("late continuation cannot append after scope revision changes", async () => {
    let complete!: (response: Response) => void;
    handler = (_path, _method, body) =>
      body?.continuation
        ? new Promise((resolve) => {
            complete = resolve;
          })
        : json({
            status: "partial",
            complete: false,
            items: [{ name: "test", system: false }],
            continuation: "TEST-CURSOR",
            limitation: null,
          });
    const render = (value: Cluster) => (
      <ScopeEditor cluster={value} onClose={() => {}} onChanged={() => {}} />
    );
    await mount(render(kubeReady));
    await click("Обновить список");
    await click("Загрузить ещё пространства имён");
    await mount(render({ ...kubeReady, access_revision: 2 }));
    await act(async () =>
      complete(
        json({
          ...completeDiscovery,
          items: [{ name: "stale-page", system: false }],
        }),
      ),
    );
    expect(container.textContent).toContain(
      "Подключение изменилось в другой операции",
    );
    expect(
      container.querySelector(
        'input[aria-label="Пространство имён stale-page"]',
      ),
    ).toBeNull();
    expect(container.textContent).toContain("Выбрано 1 из 100");
  });
});
