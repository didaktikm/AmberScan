import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  api,
  apiPath,
  ApiError,
  errorText,
  MAX_BODY_BYTES,
  onUnauthorized,
  parseApiError,
  parseReportJson,
  queryString,
  readTextFile,
  setSession,
} from "../src/api";
import {
  canAcceptRisk,
  canManage,
  canScan,
  credentialValid,
  dispositionOptions,
  elapsed,
  formatDate,
  parseNamespaces,
} from "../src/utils";
import type { Session } from "../src/types";

const session: Session = {
  user: { id: "user-id", username: "analyst", role: "auditor" },
  csrf_token: "csrf-test-token",
};
const originalFetch = globalThis.fetch;
let calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
function respond(body: unknown, status = 200) {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ input, init });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}
beforeEach(() => {
  calls = [];
  setSession(null);
  onUnauthorized(undefined);
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  setSession(null);
  onUnauthorized(undefined);
});

describe("same-origin API and CSRF", () => {
  test("GET uses /api, same-origin cookies, no-store and no CSRF header", async () => {
    respond({ clusters: 0 });
    expect(await api("/overview")).toEqual({ clusters: 0 });
    expect(calls[0].input).toBe("/api/overview");
    expect(calls[0].init?.credentials).toBe("same-origin");
    expect(calls[0].init?.cache).toBe("no-store");
    expect(calls[0].init?.redirect).toBe("error");
    expect(new Headers(calls[0].init?.headers).has("X-CSRF-Token")).toBe(false);
  });
  test("login works without a CSRF token", async () => {
    respond(session);
    await api("/login", {
      method: "POST",
      body: { username: "analyst", password: "test-only" },
    });
    expect(new Headers(calls[0].init?.headers).has("X-CSRF-Token")).toBe(false);
  });
  test.each(["POST", "PATCH", "PUT", "DELETE"] as const)(
    "%s sends the session token from memory",
    async (method) => {
      setSession(session);
      respond({ ok: true });
      await api("/resource", { method, body: { value: "текст" } });
      const headers = new Headers(calls[0].init?.headers);
      expect(headers.get("X-CSRF-Token")).toBe("csrf-test-token");
      expect(headers.get("Content-Type")).toBe("application/json");
      expect(calls[0].init?.body).toBe('{"value":"текст"}');
    },
  );
  test("mutation fails closed without a session and does not fetch", async () => {
    respond({});
    await expect(
      api("/runs", { method: "POST", body: {} }),
    ).rejects.toMatchObject({ code: "csrf_missing" });
    expect(calls).toHaveLength(0);
  });
  test("clearing the session removes the CSRF token", async () => {
    setSession(session);
    setSession(null);
    respond({});
    await expect(api("/logout", { method: "POST" })).rejects.toMatchObject({
      code: "csrf_missing",
    });
  });
  test("401 clears session and notifies the application", async () => {
    setSession(session);
    respond(
      { detail: { code: "unauthorized", message: "Session expired" } },
      401,
    );
    let notified = 0;
    onUnauthorized(() => {
      notified += 1;
    });
    await expect(api("/clusters")).rejects.toMatchObject({ status: 401 });
    expect(notified).toBe(1);
    await expect(api("/runs", { method: "POST" })).rejects.toMatchObject({
      code: "csrf_missing",
    });
  });
  test("Kubernetes authentication 409 preserves web session and typed reason", async () => {
    setSession(session);
    respond(
      {
        detail: {
          code: "kubernetes_authentication_required",
          message: "Kubernetes rejected credentials",
        },
      },
      409,
    );
    let notified = false;
    onUnauthorized(() => {
      notified = true;
    });
    await expect(
      api("/clusters/test/namespaces/discover", { method: "POST", body: {} }),
    ).rejects.toMatchObject({
      status: 409,
      code: "kubernetes_authentication_required",
    });
    expect(notified).toBe(false);
    respond({ ok: true });
    await api("/clusters/test/credential", {
      method: "POST",
      body: {
        content: "test",
        context: "test",
        storage_mode: "run_only",
        expected_access_revision: 1,
      },
    });
    expect(new Headers(calls.at(-1)?.init?.headers).get("X-CSRF-Token")).toBe(
      "csrf-test-token",
    );
  });
  test("invalid login does not invoke the session-expired callback", async () => {
    respond({ detail: "Invalid login" }, 401);
    let notified = false;
    onUnauthorized(() => {
      notified = true;
    });
    await expect(
      api("/login", { method: "POST", body: {} }),
    ).rejects.toMatchObject({ status: 401 });
    expect(notified).toBe(false);
  });
  test("enforces UTF-8 request byte limit before network access", async () => {
    setSession(session);
    respond({});
    await expect(
      api("/imports", {
        method: "POST",
        body: { data: "я".repeat(MAX_BODY_BYTES / 2) },
      }),
    ).rejects.toMatchObject({ code: "body_too_large" });
    expect(calls).toHaveLength(0);
  });
  test("supports 204 empty responses", async () => {
    setSession(session);
    globalThis.fetch = (async () =>
      new Response(null, { status: 204 })) as unknown as typeof fetch;
    expect(await api("/logout", { method: "POST" })).toBeUndefined();
  });
  test("rejects non-JSON success rather than interpreting frontend HTML as API data", async () => {
    globalThis.fetch = (async () =>
      new Response("<html>Not the API</html>")) as unknown as typeof fetch;
    await expect(api("/session")).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
  test("reports a network failure without leaking underlying details", async () => {
    globalThis.fetch = (async () => {
      throw new Error("private.internal token=SECRET");
    }) as unknown as typeof fetch;
    try {
      await api("/session");
      throw new Error("expected rejection");
    } catch (reason) {
      expect(reason).toBeInstanceOf(ApiError);
      expect(errorText(reason)).toContain("Нет соединения");
      expect(errorText(reason)).not.toContain("SECRET");
    }
  });
});

describe("API errors", () => {
  test("structured domain error preserves sanitized message and code", () => {
    const error = parseApiError(
      {
        detail: {
          code: "configuration_required",
          message: "Configure Kubernetes egress",
        },
      },
      409,
    );
    expect(error.message).toBe("Configure Kubernetes egress");
    expect(error.code).toBe("configuration_required");
    expect(error.status).toBe(409);
  });
  test("FastAPI validation arrays identify affected fields without raw input", () => {
    const error = parseApiError(
      {
        detail: [
          {
            loc: ["body", "namespaces", 0],
            msg: "Invalid namespace",
            input: "SECRET",
          },
        ],
      },
      422,
    );
    expect(error.message).toBe("Пространства имён.0: Invalid namespace");
    expect(error.message).not.toContain("SECRET");
  });
  test("known domain errors are Russian without changing machine codes", () => {
    const error = parseApiError(
      {
        detail: {
          code: "namespace_snapshot_expired",
          message: "The namespace list snapshot expired; refresh discovery.",
        },
      },
      409,
    );
    expect(error.message).toBe(
      "Срок действия списка пространств имён истёк. Обновите список.",
    );
    expect(error.code).toBe("namespace_snapshot_expired");
    expect(error.status).toBe(409);
  });
  test("broad and unknown codes retain their specific diagnostic", () => {
    for (const code of [
      "invalid_input",
      "forbidden",
      "conflict",
      "future_error",
      "constructor",
      "__proto__",
    ]) {
      const error = parseApiError(
        { detail: { code, message: "Specific diagnostic" } },
        400,
      );
      expect(error.message).toBe("Specific diagnostic");
      expect(error.code).toBe(code);
    }
  });
  test("known validation types are Russian and never expose input or context", () => {
    const error = parseApiError(
      {
        detail: [
          {
            loc: ["body", "password"],
            type: "string_too_short",
            msg: "String too short",
            input: "SECRET",
            ctx: { value: "SECRET" },
          },
          {
            loc: ["body", "timeout_seconds"],
            type: "int_parsing",
            msg: "Invalid integer",
          },
          null,
        ],
      },
      422,
    );
    expect(error.message).toContain("Пароль: Значение короче допустимого.");
    expect(error.message).toContain("Лимит времени: Введите целое число.");
    expect(error.message).not.toContain("SECRET");
    expect(error.message).not.toContain("String too short");
  });
  test("malformed details use safe fallback text", () => {
    expect(
      parseApiError({ detail: { traceback: "SECRET" } }, 500).message,
    ).not.toContain("SECRET");
    expect(parseApiError("<html>SECRET</html>", 403).message).toContain(
      "Недостаточно прав",
    );
    expect(parseApiError(null, 404).message).toContain("не найден");
  });
});

describe("paths", () => {
  test.each([
    "https://example.test",
    "//example.test",
    "/\\example.test",
    "/x/../logout",
    "/foo#bar",
    "/foo bar",
  ])("blocks unsafe API path %s", (path) => {
    expect(() => apiPath(path)).toThrow();
  });
  test("builds and encodes query parameters", () => {
    expect(
      queryString({ q: " a&b ", severity: "", cluster_id: undefined }),
    ).toBe("?q=a%26b");
    expect(queryString({ q: "" })).toBe("");
  });
});

describe("bounded report import", () => {
  test("only accepts a JSON object", () => {
    expect(parseReportJson('{"SchemaVersion":2}')).toEqual({
      SchemaVersion: 2,
    });
    for (const value of ["null", "[]", '"hello"', "{", "true", "1"])
      expect(() => parseReportJson(value)).toThrow();
  });
  test("rejects empty and oversize files before reading", async () => {
    await expect(readTextFile(new File([], "empty.json"))).rejects.toThrow(
      "пуст",
    );
    await expect(
      readTextFile(new File(["x".repeat(900_001)], "large.json")),
    ).rejects.toThrow("900");
  });
  test("enforces a separate kubeconfig file cap", async () => {
    await expect(
      readTextFile(new File(["x".repeat(262_145)], "large.yaml"), 262_144),
    ).rejects.toThrow("256");
  });
  test("reads a bounded UTF-8 file", async () => {
    expect(await readTextFile(new File(["тест"], "config.yaml"))).toBe("тест");
  });
});

describe("explicit namespace scope and roles", () => {
  test("normalizes and deduplicates explicit namespaces", () => {
    expect(parseNamespaces("app, system\napp\tpayments")).toEqual([
      "app",
      "system",
      "payments",
    ]);
  });
  test.each(["", "*", "ALL", "-app", "app-", "a/b", "a".repeat(64)])(
    "rejects invalid scope %s",
    (scope) => {
      expect(() => parseNamespaces(scope)).toThrow();
    },
  );
  test("limits explicit scope to 100 namespaces", () => {
    expect(() =>
      parseNamespaces(
        Array.from({ length: 101 }, (_, index) => `ns-${index}`).join(","),
      ),
    ).toThrow("100");
  });
  test("viewer cannot scan, import, export or change dispositions", () => {
    expect(canScan("viewer")).toBe(false);
    expect(canManage("viewer")).toBe(false);
    expect(dispositionOptions("viewer")).toEqual([]);
  });
  test("auditor may confirm only; security lead may accept risk", () => {
    expect(dispositionOptions("auditor")).toEqual(["confirmed"]);
    expect(canAcceptRisk("auditor")).toBe(false);
    expect(canAcceptRisk("security_lead")).toBe(true);
    expect(canManage("security_lead")).toBe(false);
  });
  test("administrator can manage connections", () => {
    expect(canManage("administrator")).toBe(true);
    expect(canScan("administrator")).toBe(true);
  });
});

describe("honest timestamps", () => {
  test("does not invent a duration for queued jobs", () => {
    expect(
      elapsed({ started_at: null, finished_at: null, status: "queued" }),
    ).toBe("Не начат");
  });
  test("uses actual start and finish", () => {
    expect(
      elapsed({
        started_at: "2026-01-01T00:00:00Z",
        finished_at: "2026-01-01T00:02:03Z",
        status: "completed",
      }),
    ).toBe("2 мин 3 с");
  });
  test("only active runs use current time", () => {
    expect(
      elapsed(
        {
          started_at: "2026-01-01T00:00:00Z",
          finished_at: null,
          status: "running",
        },
        Date.parse("2026-01-01T00:00:12Z"),
      ),
    ).toBe("12 с");
    expect(
      elapsed({
        started_at: "2026-01-01T00:00:00Z",
        finished_at: null,
        status: "failed",
      }),
    ).toContain("не передано");
  });
  test("rejects impossible duration", () => {
    expect(
      elapsed({ started_at: "bad", finished_at: "bad", status: "completed" }),
    ).toBe("—");
  });
  test("missing dates and credentials remain unknown", () => {
    expect(formatDate(null)).toBe("—");
    expect(credentialValid(null)).toBe(false);
    expect(credentialValid("bad")).toBe(false);
    expect(credentialValid("2000-01-01T00:00:00Z")).toBe(false);
  });
});
