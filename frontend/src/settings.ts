import { ApiError } from "./api";
import type { EgressRule } from "./types";

export const purposeLabels: Record<EgressRule["purpose"], string> = {
  kubernetes: "Kubernetes API",
  registry: "Реестр образов",
  database: "База данных",
};
export interface RuleDraft {
  id: string;
  purpose: EgressRule["purpose"];
  host: string;
  port: string;
  cidrs: string;
}
export function ruleDraft(rule?: EgressRule): RuleDraft {
  return rule
    ? { ...rule, port: String(rule.port), cidrs: rule.cidrs.join("\n") }
    : { id: "", purpose: "kubernetes", host: "", port: "443", cidrs: "" };
}
export function policyRules(drafts: RuleDraft[]): EgressRule[] {
  if (drafts.length > 128)
    throw new Error("Допускается до 128 правил исходящих подключений.");
  const ids = new Set<string>();
  return drafts.map((draft) => {
    const id = draft.id.trim(),
      host = draft.host.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(id) || ids.has(id))
      throw new Error(
        "У каждого правила должен быть уникальный идентификатор: буквы, цифры, дефисы, подчёркивания, до 100 символов.",
      );
    ids.add(id);
    // The server validates exact DNS/IP hosts, strict CIDRs and the deployment ceiling.
    if (!host || /[\s/*@?#]/.test(host) || host.includes("://"))
      throw new Error(
        "Адрес узла — точное DNS-имя или IP без схемы, пути, масок и учётных данных. Порт указывается отдельно.",
      );
    const port = Number(draft.port);
    if (
      !/^\d+$/.test(draft.port) ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    )
      throw new Error("Порт должен быть целым числом от 1 до 65535.");
    const cidrs = [...new Set(draft.cidrs.split(/[\s,]+/).filter(Boolean))];
    if (
      !cidrs.length ||
      cidrs.length > 64 ||
      cidrs.some((cidr) => !/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(cidr))
    )
      throw new Error(
        "Укажите от 1 до 64 явных CIDR-сетей для каждого узла. Сервер проверит адреса и границы сетей.",
      );
    return { id, purpose: draft.purpose, host, port, cidrs };
  });
}
export function recentReauthentication(
  until?: string | null,
  now = Date.now(),
) {
  return (
    !!until && Number.isFinite(Date.parse(until)) && Date.parse(until) > now
  );
}
export function adminError(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "reauthentication_required")
      return "Подтвердите пароль администратора: срок подтверждения истёк.";
    if (error.code === "reauthentication_failed")
      return "Пароль не подтверждён. Проверьте пароль локальной учётной записи.";
    if (error.status === 409)
      return "Настройки или доступ изменились. Закройте подтверждение и форму, обновите данные и проверьте изменения заново.";
    return error.message;
  }
  return "Действие не выполнено. Обновите данные перед повтором.";
}
