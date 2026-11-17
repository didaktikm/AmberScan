import { useState, type FormEvent, type ReactNode } from "react";
import { LockKeyhole } from "lucide-react";
import { api, ApiError } from "./api";
import { useClock } from "./hooks";
import { adminError, recentReauthentication } from "./settings";
import { ErrorBox, Modal, Notice } from "./ui";
import { formatDate } from "./utils";

/** Password and reauthentication window exist only in component memory. */
export function AdminConfirmation({
  title,
  confirmLabel,
  children,
  warning,
  danger = false,
  initialUntil,
  onReauthenticated,
  onConfirm,
  onClose,
}: {
  title: string;
  confirmLabel: string;
  children?: ReactNode;
  warning: string;
  danger?: boolean;
  initialUntil?: string | null;
  onReauthenticated?: (until: string) => void;
  onConfirm: () => Promise<void>;
  onClose: () => void;
}) {
  const [until, setUntil] = useState(initialUntil);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const now = useClock(true);
  const recent = recentReauthentication(until, now);
  async function confirm(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      if (!recentReauthentication(until)) {
        if (!password) {
          setError("Введите пароль администратора для подтверждения действия.");
          return;
        }
        const result = await api<{ reauthenticated_until: string }>(
          "/admin/reauth",
          {
            method: "POST",
            body: { password },
          },
        );
        setPassword("");
        setUntil(result.reauthenticated_until);
        onReauthenticated?.(result.reauthenticated_until);
      }
      await onConfirm();
    } catch (reason) {
      if (
        reason instanceof ApiError &&
        reason.code === "reauthentication_required"
      )
        setUntil(null);
      setError(adminError(reason));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }
  return (
    <Modal
      title={title}
      subtitle="Проверьте действие перед отправкой запроса."
      wide
      busy={busy}
      onClose={onClose}
    >
      <form className="form-stack" onSubmit={confirm}>
        {children}
        <Notice tone="warning">{warning}</Notice>
        <ErrorBox message={error} />
        <div className="reauth-box">
          <LockKeyhole size={20} aria-hidden="true" />
          <div className="form-stack">
            {recent ? (
              <p className="small">
                Пароль подтверждён до {formatDate(until)}. Сервер повторно
                проверит права и срок подтверждения.
              </p>
            ) : (
              <label>
                Пароль администратора
                <input
                  type="password"
                  autoComplete="current-password"
                  required
                  maxLength={256}
                  value={password}
                  disabled={busy}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <small>
                  Пароль вашей локальной учётной записи AmberData.
                  Подтверждение действует до 5 минут; пароль не сохраняется.
                </small>
              </label>
            )}
          </div>
        </div>
        <div className="modal-footer">
          <button
            type="button"
            className="button button-secondary"
            disabled={busy}
            onClick={onClose}
          >
            Вернуться
          </button>
          <button
            type="submit"
            className={`button ${danger ? "button-danger" : "button-primary"}`}
            disabled={busy}
          >
            {busy ? "Выполняется запрос…" : confirmLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}
