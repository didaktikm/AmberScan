import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import {
  addNamespaces,
  connectionDraftId,
  coverageOutcome,
  isSystemNamespace,
  namespaceDiscovery,
  preflightCoverage,
  selectedNamespaces,
} from "../src/namespaces";
import { NamespacePicker } from "../src/NamespacePicker";
import { NamespaceCoverage, NamespaceError } from "../src/NamespaceAccess";
import { ApiError } from "../src/api";
import type { Coverage } from "../src/types";

const allowed: Coverage = {
  check: "test/pods",
  namespace: "test",
  resource: "pods",
  status: "completed",
  detail: "Allowed",
  code: "allowed",
};
const denied: Coverage = {
  ...allowed,
  resource: "services",
  status: "denied",
  code: "http_403",
  detail: "Denied",
};

describe("namespace scope contracts", () => {
  test("requires nonempty distinct explicit allowlist subset", () => {
    expect(selectedNamespaces(["team-a"], ["team-a", "team-b"])).toEqual([
      "team-a",
    ]);
    for (const values of [
      [],
      ["*"],
      ["team-a", "team-a"],
      ["TEAM-A"],
      [" team-a"],
      ["team-a,team-b"],
    ])
      expect(() => selectedNamespaces(values)).toThrow();
    expect(() => selectedNamespaces(["team-c"], ["team-a"])).toThrow(
      "подмножеством",
    );
  });
  test("selection union never silently truncates at 100", () => {
    const hundred = Array.from({ length: 100 }, (_, index) => `team-${index}`);
    expect(addNamespaces(hundred, ["team-2"])).toEqual(hundred);
    expect(() => addNamespaces(hundred, ["another"])).toThrow("100");
    expect(hundred).toHaveLength(100);
  });
  test("only known system names get the system badge", () => {
    for (const name of ["kube-system", "kube-public", "kube-node-lease"])
      expect(isSystemNamespace(name)).toBe(true);
    expect(isSystemNamespace("kube-team")).toBe(false);
    expect(isSystemNamespace("default")).toBe(false);
  });
  test("same-origin resume accepts only the exact UUID hash", () => {
    const id = "12345678-1234-1234-abcd-123456789abc";
    expect(connectionDraftId(`#connection-draft=${id}`)).toBe(id);
    for (const value of [
      `https://evil.example/#connection-draft=${id}`,
      `#connection-draft=${id}&return=https://evil.example`,
      `#connection-draft=${id}/x`,
      "#connection-draft=../../clusters",
      "#connection-draft=token",
      "#connection-draft=%31",
      "#connection-draft=",
      "#workspace-main",
    ])
      expect(connectionDraftId(value)).toBeUndefined();
  });
});

describe("fail-closed coverage", () => {
  test("only explicit allowed or mixed allowed/http403 permits proceeding", () => {
    expect(coverageOutcome()).toBe("unchecked");
    expect(coverageOutcome([])).toBe("failed");
    expect(coverageOutcome([allowed])).toBe("allowed");
    expect(coverageOutcome([allowed, denied])).toBe("partial");
    expect(coverageOutcome([denied])).toBe("failed");
    expect(coverageOutcome([{ ...allowed, code: undefined }])).toBe("failed");
    expect(coverageOutcome([{ ...denied, code: "allowed" }])).toBe("failed");
  });
  test.each([
    "http_401",
    "http_tls",
    "http_network",
    "http_timeout",
    "egress_denied",
    "malformed",
    "unsupported",
    "not_checked",
  ])("%s cannot be accepted as partial", (code) => {
    expect(coverageOutcome([allowed, { ...denied, code }])).toBe("failed");
    const markup = renderToStaticMarkup(
      <NamespaceCoverage
        coverage={[allowed, { ...denied, code }]}
        onAcceptPartial={() => {}}
      />,
    );
    expect(markup).not.toContain('type="checkbox"');
    expect(markup).toContain("Продолжение заблокировано");
  });
  test("typed Kubernetes auth error offers personal kubeconfig reimport, not web logout", () => {
    const markup = renderToStaticMarkup(
      <NamespaceError
        error={
          new ApiError(
            "Credentials rejected",
            409,
            "kubernetes_authentication_required",
          )
        }
      />,
    );
    expect(markup).toContain("Повторно импортируйте kubeconfig");
    expect(markup).not.toContain("OIDC");
    expect(markup).toContain("AmberData не завершена");
  });
  test("malformed discovery or coverage never becomes successful empty data", () => {
    for (const value of [
      null,
      {},
      { status: "complete", complete: true, items: null },
      { status: "forbidden", complete: true, items: [], limitation: null },
      {
        status: "complete",
        complete: true,
        items: [{ name: "*", system: false }],
        limitation: null,
      },
    ])
      expect(() => namespaceDiscovery(value)).toThrow();
    expect(
      namespaceDiscovery({
        status: "complete",
        complete: true,
        items: [],
        limitation: null,
      }).items,
    ).toEqual([]);
    for (const value of [
      null,
      {},
      { coverage: null },
      { coverage: [null] },
      { coverage: [{ status: "completed" }] },
    ])
      expect(() => preflightCoverage(value)).toThrow();
  });
  test("preflight 401 has an explicit personal kubeconfig recovery prompt", () => {
    const markup = renderToStaticMarkup(
      <NamespaceCoverage coverage={[{ ...denied, code: "http_401" }]} />,
    );
    expect(markup).toContain("Повторно импортируйте kubeconfig");
    expect(markup).toContain("AmberData не завершена");
  });
  test("not loaded, complete-empty, partial and forbidden are distinct", () => {
    const picker = (props: object) =>
      renderToStaticMarkup(
        <NamespacePicker
          selected={[]}
          onChange={() => {}}
          options={[]}
          {...props}
        />,
      );
    expect(picker({ loaded: false })).toContain("ещё не получен");
    expect(picker({ loaded: true, complete: true })).toContain(
      "Получен пустой список",
    );
    expect(picker({ loaded: true, complete: false })).toContain(
      "неполный список",
    );
    expect(picker({ forbidden: true })).toContain(
      "Это не означает, что кластер пуст",
    );
  });
});
