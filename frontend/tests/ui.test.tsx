import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import { FindingDialog } from "../src/pages/Findings";
import { CoverageTable, Pagination } from "../src/ui";
import type { Cluster, Finding, User } from "../src/types";
import { AuthorizationChoice } from "../src/CredentialRecovery";
import { ClusterWizard } from "../src/ConnectionWizard";
import { RunLaunch } from "../src/RunLaunch";
import { ScopeEditor } from "../src/ScopeEditor";
import { NamespaceCoverage } from "../src/NamespaceAccess";
import { parseNamespaces } from "../src/utils";
import { policyRules, purposeLabels, ruleDraft } from "../src/settings";

const finding: Finding = {
  id: "test-finding",
  rule_id: "CVE-test",
  title: "<script>alert(1)</script>",
  severity: "high",
  namespace: "test",
  resource_kind: "image",
  resource_name: "test-image",
  resource_uid: "",
  category: "vulnerability",
  scanner: "trivy",
  evidence: { untrusted: '<img src=x onerror="alert(1)">' },
  recommendation: "<b>Upgrade</b>",
  confidence: "high",
  package: {
    name: "libexample",
    installed_version: "1.0",
    fixed_version: "2.0",
  },
  run_id: "test-run",
  cluster_id: "test-cluster",
  cluster_name: "Test-only fixture",
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-01T00:00:00Z",
  disposition: "open",
};
const user: User = { id: "test-user", username: "unit-test", role: "viewer" };

describe("safe evidence and role rendering", () => {
  test("renders imported package objects as text, not React objects", () => {
    const markup = renderToStaticMarkup(
      <FindingDialog finding={finding} user={user} onClose={() => {}} />,
    );
    expect(markup).toContain("libexample");
    expect(markup).toContain("installed_version");
    expect(markup).toContain("2.0");
  });
  test("never executes untrusted finding title, recommendation or evidence HTML", () => {
    const markup = renderToStaticMarkup(
      <FindingDialog finding={finding} user={user} onClose={() => {}} />,
    );
    expect(markup).not.toContain("<script>");
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<b>Upgrade</b>");
    expect(markup).toContain("&lt;script&gt;");
    expect(markup).toContain("&lt;img");
    expect(markup).toContain("&lt;b&gt;Upgrade");
  });
  test("viewer sees evidence but no disposition mutation form", () => {
    const markup = renderToStaticMarkup(
      <FindingDialog finding={finding} user={user} onClose={() => {}} />,
    );
    expect(markup).toContain("Доказательства");
    expect(markup).not.toContain("Сохранить решение");
  });
  test("auditor cannot choose accepted risk", () => {
    const markup = renderToStaticMarkup(
      <FindingDialog
        finding={finding}
        user={{ ...user, role: "auditor" }}
        onClose={() => {}}
      />,
    );
    expect(markup).toContain('value="confirmed"');
    expect(markup).not.toContain('value="accepted_risk"');
    expect(markup).not.toContain('value="false_positive"');
  });
  test("security lead can choose risk or false positive", () => {
    const markup = renderToStaticMarkup(
      <FindingDialog
        finding={finding}
        user={{ ...user, role: "security_lead" }}
        onClose={() => {}}
      />,
    );
    expect(markup).toContain('value="accepted_risk"');
    expect(markup).toContain('value="false_positive"');
  });
});

describe("Russian display copy preserves technical data", () => {
  const cluster: Cluster = {
    id: "copy-test",
    name: "context-credentials-production",
    context: "production-context",
    environment: "production",
    server: "https://kubernetes.example",
    status: "authorized",
    created_at: "2026-01-01T00:00:00Z",
    credential_expires_at: "2099-01-01T00:00:00Z",
    namespaces: ["credentials-namespace"],
    lifecycle: "ready",
    access_revision: 1,
    auth_type: "kubeconfig",
    storage_mode: "run_only",
  };

  test("wizard, authorization and scope use consistent Russian terminology", () => {
    const authorization = renderToStaticMarkup(
      <AuthorizationChoice value="run_only" onChange={() => {}} />,
    );
    expect(authorization).toContain("Получение списка и проверка доступа");
    expect(authorization).toContain("Учётные данные не сохраняются в браузере");
    expect(authorization).toContain('value="run_only"');
    expect(authorization).toContain('value="persistent"');

    const wizard = renderToStaticMarkup(
      <ClusterWizard
        user={user}
        capabilitiesLoading={false}
        reloadCapabilities={() => {}}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    expect(wizard).toContain("выбор пространств имён → проверка доступа");
    expect(wizard).toContain("личные учётные данные выбранного контекста");
    expect(wizard).not.toContain("credentials");
    expect(wizard).not.toContain("egress");

    const scope = renderToStaticMarkup(
      <ScopeEditor cluster={cluster} onClose={() => {}} onChanged={() => {}} />,
    );
    expect(scope).toContain("Изменить разрешённые пространства имён");
    expect(scope).toContain("списка разрешённых пространств имён подключения");
    expect(scope).toContain("context-credentials-production");
  });

  test("run labels are Russian while cluster context and namespace names stay exact", () => {
    const markup = renderToStaticMarkup(
      <RunLaunch
        clusters={[cluster]}
        initialCluster={cluster.id}
        onClose={() => {}}
        onCreated={() => {}}
      />,
    );
    expect(markup).toContain("Контекст:");
    expect(markup).toContain("Проверить выбранные пространства имён");
    expect(markup).toContain("production-context");
    expect(markup).toContain(
      'aria-label="Пространство имён credentials-namespace"',
    );
    expect(markup).not.toContain("read-only");
  });

  test("coverage labels translate, scanner prose and protocol fields remain verbatim", () => {
    const markup = renderToStaticMarkup(
      <NamespaceCoverage
        coverage={[
          {
            check: "credentials-namespace/pods",
            namespace: "credentials-namespace",
            resource: "pods",
            group: "apps",
            verb: "get",
            status: "completed",
            code: "allowed",
            detail: "External scanner: namespace credentials context preflight",
          },
        ]}
      />,
    );
    expect(markup).toContain('aria-label="Результат проверки доступа"');
    expect(markup).toContain("Пространство имён: credentials-namespace");
    expect(markup).toContain("apps · get");
    expect(markup).toContain(
      "External scanner: namespace credentials context preflight",
    );
  });

  test("validation and settings labels are Russian without translating rule identifiers", () => {
    expect(() => parseNamespaces("")).toThrow("хотя бы одно пространство имён");
    expect(() => parseNamespaces("*")).toThrow("Имя пространства имён");
    expect(purposeLabels.registry).toBe("Реестр образов");
    const rule = {
      ...ruleDraft(),
      id: "registry-rule",
      purpose: "registry" as const,
      host: "registry.example",
      port: "443",
      cidrs: "10.0.0.0/8",
    };
    expect(policyRules([rule])[0]).toEqual({
      id: "registry-rule",
      purpose: "registry",
      host: "registry.example",
      port: 443,
      cidrs: ["10.0.0.0/8"],
    });
    expect(() =>
      policyRules([{ ...rule, host: "https://registry.example" }]),
    ).toThrow("Адрес узла — точное DNS-имя или IP");
  });

  test("finding labels are Russian and imported source content stays untouched", () => {
    const markup = renderToStaticMarkup(
      <FindingDialog
        finding={{ ...finding, image_digest: "sha256:abcdef" }}
        user={user}
        onClose={() => {}}
      />,
    );
    expect(markup).toContain("Пространство имён");
    expect(markup).toContain("Хеш образа");
    expect(markup).toContain("sha256:abcdef");
    expect(markup).toContain("vulnerability");
    expect(markup).toContain("trivy");
    expect(markup).toContain("&lt;b&gt;Upgrade");
  });
});

describe("honest coverage", () => {
  test("missing coverage is not success", () => {
    const markup = renderToStaticMarkup(<CoverageTable coverage={[]} />);
    expect(markup).toContain("не означает, что все проверки пройдены");
    expect(markup).not.toContain("badge-good");
  });
  test("denied coverage is explicitly labeled", () => {
    const markup = renderToStaticMarkup(
      <CoverageTable
        coverage={[
          { check: "pods/test", status: "denied", detail: "RBAC denied" },
        ]}
      />,
    );
    expect(markup).toContain("Нет доступа");
    expect(markup).toContain("RBAC denied");
  });
  test("pagination exposes the API window limit", () => {
    const markup = renderToStaticMarkup(
      <Pagination offset={500} count={4} loading={false} onChange={() => {}} />,
    );
    expect(markup).toContain("Страница 2");
    expect(markup).toContain("500");
    expect(markup).toContain("получено 4");
  });
});
