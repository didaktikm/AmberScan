import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { SettingsPage, PolicyPreview } from "../src/pages/Settings";
import { AdminConfirmation } from "../src/AdminConfirmation";
import { ClusterDetail } from "../src/pages/Clusters";
import {
  policyRules,
  recentReauthentication,
  ruleDraft,
} from "../src/settings";
import type { Cluster, User } from "../src/types";

const administrator: User = {
  id: "test-admin",
  username: "test-admin",
  role: "administrator",
};
const cluster: Cluster = {
  id: "test-cluster",
  lifecycle: "ready",
  access_revision: 1,
  name: "Test-only cluster",
  environment: "test",
  context: "test-context",
  server: "https://cluster.example",
  status: "authorized",
  created_at: "2026-01-01T00:00:00Z",
  credential_expires_at: "2099-01-01T00:00:00Z",
  storage_mode: "run_only",
  auth_type: "kubeconfig",
  namespaces: ["test"],
};
describe("B1 egress and reauthentication contract", () => {
  const rule = {
    ...ruleDraft(),
    id: "kubernetes",
    host: "kubernetes.example",
    cidrs: "10.20.0.0/24\n10.20.0.0/24,2001:db8::/32",
  };
  test("preserves exact per-purpose host/port/CIDR association", () => {
    expect(policyRules([rule])).toEqual([
      {
        id: "kubernetes",
        purpose: "kubernetes",
        host: "kubernetes.example",
        port: 443,
        cidrs: ["10.20.0.0/24", "2001:db8::/32"],
      },
    ]);
    expect(policyRules([])).toEqual([]);
  });
  test("rejects duplicate ids, wildcards, paths, invalid ports and missing CIDRs", () => {
    expect(() => policyRules([rule, rule])).toThrow("уникальный");
    for (const host of [
      "*.example",
      "https://kubernetes.example",
      "kubernetes.example/path",
      "user@kubernetes.example",
    ])
      expect(() => policyRules([{ ...rule, host }])).toThrow();
    for (const port of ["0", "65536", "443.1", ""])
      expect(() => policyRules([{ ...rule, port }])).toThrow("Порт");
    expect(() => policyRules([{ ...rule, cidrs: "" }])).toThrow("CIDR");
  });
  test("reauthentication cannot be inferred from missing, invalid or expired timestamps", () => {
    const now = Date.parse("2026-01-01T00:00:00Z");
    for (const until of [undefined, null, "invalid", "2026-01-01T00:00:00Z"])
      expect(recentReauthentication(until, now)).toBe(false);
    expect(recentReauthentication("2026-01-01T00:05:00Z", now)).toBe(true);
  });
});

describe("B1 safe and honest rendered UI", () => {
  test("non-admin Settings contains guidance without mutation controls", () => {
    const markup = renderToStaticMarkup(
      <SettingsPage user={{ ...administrator, role: "auditor" }} />,
    );
    expect(markup).toContain("Попросите администратора");
    expect(markup).not.toContain("Добавить провайдера");
    expect(markup).not.toContain('type="password"');
  });
  test("admin confirmation requires password unless recent server-confirmed window exists", () => {
    const markup = renderToStaticMarkup(
      <AdminConfirmation
        title="Test action"
        warning="Test warning"
        confirmLabel="Confirm"
        onConfirm={async () => {}}
        onClose={() => {}}
      />,
    );
    expect(markup).toContain('type="password"');
    expect(markup).toContain("Пароль администратора");
    expect(markup).toContain("локальной учётной записи AmberData");
    expect(markup).not.toContain("Client secret");
    expect(markup).not.toContain("OIDC");
  });
  test("auditor can reimport and revoke only their personal authorization", () => {
    const markup = renderToStaticMarkup(
      <ClusterDetail
        cluster={cluster}
        user={{ ...administrator, role: "auditor" }}
        onClose={() => {}}
        onChanged={() => {}}
        onLaunch={() => {}}
      />,
    );
    expect(markup).toContain("Повторно импортировать kubeconfig");
    expect(markup).toContain("Отозвать мою авторизацию");
    expect(markup).not.toContain("Отозвать авторизации всех пользователей");
  });
  test("admin personal and all-cluster revocation are distinct; viewer has neither", () => {
    const props = {
      cluster,
      onClose: () => {},
      onChanged: () => {},
      onLaunch: () => {},
    };
    const admin = renderToStaticMarkup(
      <ClusterDetail {...props} user={administrator} />,
    );
    expect(admin).toContain("Отозвать мою авторизацию");
    expect(admin).toContain("Отозвать авторизации всех пользователей");
    const viewer = renderToStaticMarkup(
      <ClusterDetail {...props} user={{ ...administrator, role: "viewer" }} />,
    );
    expect(viewer).not.toContain("Отозвать мою авторизацию");
    expect(viewer).not.toContain("authorization-storage");
  });
});

describe("kubeconfig-only UI", () => {
  test("settings and cluster detail have no identity provider controls", () => {
    const markup = renderToStaticMarkup(
      <>
        <SettingsPage user={administrator} />
        <ClusterDetail
          cluster={cluster}
          user={administrator}
          onClose={() => {}}
          onChanged={() => {}}
          onLaunch={() => {}}
        />
      </>,
    );
    for (const removed of [
      "OIDC",
      "Callback",
      "Redirect URI",
      "Провайдер",
      "Client secret",
      "Авторизовать заново",
    ])
      expect(markup).not.toContain(removed);
    expect(markup).toContain("Повторно импортировать kubeconfig");
  });
  test("egress preview escapes untrusted host text", () => {
    const markup = renderToStaticMarkup(
      <PolicyPreview
        rules={[
          {
            id: "test",
            purpose: "kubernetes",
            host: "<script>test-only</script>",
            port: 443,
            cidrs: ["10.0.0.0/8"],
          },
        ]}
      />,
    );
    expect(markup).not.toContain("<script>");
    expect(markup).toContain("&lt;script&gt;");
  });
});
