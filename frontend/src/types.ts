export type Role = "administrator" | "auditor" | "viewer" | "security_lead";
export interface User {
  id: string;
  username: string;
  role: Role;
}
export interface Session {
  user: User;
  csrf_token: string;
  reauthenticated_until?: string | null;
}
export type AuthType = "kubeconfig";
export type StorageMode = "run_only" | "persistent";
export interface EgressRule {
  id: string;
  purpose: "kubernetes" | "registry" | "database";
  host: string;
  port: number;
  cidrs: string[];
}
export interface EgressPolicy {
  revision: number;
  rules: EgressRule[];
  legacy_imported: boolean;
}
export interface AdminSetup {
  policy: EgressPolicy;
  reauthenticated_until?: string | null;
  legacy_configuration_available: boolean;
}
export interface Feature {
  id: string;
  title: string;
  status: string;
  detail: string;
}
export interface Capabilities {
  version: string;
  features: Feature[];
  limits: Record<string, unknown>;
  setup_required?: boolean;
  kubernetes_setup_required?: boolean;
}
export interface Overview {
  clusters: number;
  runs: number;
  findings: number;
  coverage_gaps: number;
  workers: Array<Record<string, unknown>>;
}
export interface Cluster {
  id: string;
  name: string;
  environment: string;
  context: string;
  server: string;
  status: string;
  created_at: string;
  credential_expires_at?: string | null;
  storage_mode?: StorageMode | null;
  auth_type: AuthType;
  credential_kind?: "token" | "client_certificate" | null;
  namespaces: string[];
  lifecycle: "draft" | "ready";
  access_revision: number;
  namespace_hint?: string | null;
  draft_expires_at?: string | null;
}
export interface NamespaceOption {
  name: string;
  system: boolean;
  phase?: string | null;
}
export interface NamespaceDiscovery {
  status: "complete" | "partial" | "forbidden";
  items: NamespaceOption[];
  complete: boolean;
  limitation: string | null;
  continuation?: string | null;
  namespace_hint?: string | null;
}
export interface ScopeResult {
  cluster: Cluster;
  coverage: Coverage[];
}
export interface KubeContext {
  context: string;
  cluster_name: string;
  server: string;
  username: string;
  auth_type: string;
  warnings: string[];
  namespace_hint?: string | null;
}
export interface Coverage {
  check: string;
  status: "completed" | "denied" | "error" | "not_checked" | "unsupported";
  detail: string;
  code?: string;
  namespace?: string;
  resource?: string;
  group?: string;
  verb?: string;
}
export type RunStatus =
  | "queued"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "cancelled"
  | "interrupted";
export interface Run {
  id: string;
  cluster_id: string;
  cluster_name: string;
  status: RunStatus;
  stage: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  cancel_requested: boolean;
  coverage: Coverage[];
  limitations: string[];
  versions: Record<string, unknown>;
  findings?: Finding[];
  namespaces?: string[];
  scope?: Record<string, unknown>;
  source?: string;
  scanner?: string;
}
export type Severity =
  "critical" | "high" | "medium" | "low" | "info" | "unknown";
export type Disposition =
  "open" | "confirmed" | "accepted_risk" | "false_positive";
export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  namespace: string;
  resource_kind: string;
  resource_name: string;
  resource_uid: string;
  category: string;
  scanner: string;
  evidence: Record<string, unknown>;
  recommendation: string;
  confidence: "high" | "medium" | "low";
  image_digest?: string;
  package?: string | Record<string, unknown>;
  vulnerability_id?: string;
  location?: string;
  run_id: string;
  cluster_id: string;
  cluster_name: string;
  first_seen: string;
  last_seen: string;
  disposition: Disposition;
  internal_priority?: string;
}
export interface AuditEvent {
  id: string;
  created_at: string;
  actor: string;
  action: string;
  target: string;
  detail: unknown;
}
export type Page =
  | "overview"
  | "clusters"
  | "runs"
  | "findings"
  | "imports"
  | "modes"
  | "audit"
  | "settings";
