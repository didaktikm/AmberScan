import { useState, type FormEvent } from "react";
import { Network, Plus, RefreshCw, Trash2 } from "lucide-react";
import { api, errorText } from "../api";
import { AdminConfirmation } from "../AdminConfirmation";
import { useResource } from "../hooks";
import {
  policyRules,
  purposeLabels,
  ruleDraft,
  type RuleDraft,
} from "../settings";
import { ErrorBox, Modal, Notice, PageHeader, Panel, Spinner } from "../ui";
import { canManage } from "../utils";
import type { AdminSetup, EgressPolicy, EgressRule, User } from "../types";
const policyWarning =
  "Изменение политики исходящих подключений отзовёт все личные учётные данные. Ожидающие задания будут отменены, для активных будет запрошена отмена. Пустая политика запрещает все внешние подключения.";

export function PolicyPreview({ rules }: { rules: EgressRule[] }) {
  return rules.length ? (
    <ul className="policy-preview">
      {rules.map((rule) => (
        <li key={rule.id}>
          <strong>
            {purposeLabels[rule.purpose]} · {rule.host} · порт {rule.port}
          </strong>
          <span>{rule.id}</span>
          <code>{rule.cidrs.join(", ")}</code>
        </li>
      ))}
    </ul>
  ) : (
    <Notice tone="warning">
      Правил нет. Все внешние подключения будут запрещены.
    </Notice>
  );
}

function PolicyEditor({
  policy,
  onCancel,
  onPreview,
}: {
  policy: EgressPolicy;
  onCancel: () => void;
  onPreview: (rules: EgressRule[]) => void;
}) {
  const [rules, setRules] = useState(() => policy.rules.map(ruleDraft));
  const [error, setError] = useState<string>();
  function update(index: number, field: keyof RuleDraft, value: string) {
    setRules((current) =>
      current.map((rule, position) =>
        position === index ? { ...rule, [field]: value } : rule,
      ),
    );
  }
  function preview(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    try {
      onPreview(policyRules(rules));
    } catch (reason) {
      setError(errorText(reason));
    }
  }
  return (
    <section
      className="settings-editor"
      aria-label="Редактор политики исходящих подключений"
    >
      <div className="settings-section-heading">
        <div>
          <h2>Изменить политику исходящих подключений</h2>
          <p>
            Точные узлы, порты и допустимые IP-сети для исходящих
            HTTPS-запросов.
          </p>
        </div>
        <span className="tag">Ревизия {policy.revision}</span>
      </div>
      <form className="form-stack" onSubmit={preview}>
        <Notice>
          Каждое правило связывает назначение, узел и порт только со своими
          CIDR. Все IP из DNS-ответа должны входить в эти сети. Правила не
          обходят серверные запреты и ограничения развёртывания.
        </Notice>
        <ErrorBox message={error} />
        {rules.map((rule, index) => (
          <fieldset className="egress-rule settings-fieldset" key={index}>
            <legend>Правило {index + 1}</legend>
            <div className="form-columns">
              <label>
                Идентификатор правила
                <input
                  required
                  maxLength={100}
                  pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,99}"
                  value={rule.id}
                  onChange={(event) => update(index, "id", event.target.value)}
                  placeholder="kubernetes-api"
                />
              </label>
              <label>
                Назначение
                <select
                  value={rule.purpose}
                  onChange={(event) =>
                    update(index, "purpose", event.target.value)
                  }
                >
                  {Object.entries(purposeLabels).map(([value, label]) => (
                    <option value={value} key={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="egress-endpoint">
              <label>
                Точный адрес узла
                <input
                  required
                  maxLength={253}
                  value={rule.host}
                  onChange={(event) =>
                    update(index, "host", event.target.value)
                  }
                  placeholder="kubernetes.example"
                  spellCheck={false}
                />
                <small>
                  DNS-имя или IPv4/IPv6 без https:// и пути. Не маска.
                </small>
              </label>
              <label>
                Порт
                <input
                  required
                  type="number"
                  min={1}
                  max={65535}
                  value={rule.port}
                  onChange={(event) =>
                    update(index, "port", event.target.value)
                  }
                />
                <small>HTTPS: 443; Kubernetes часто 6443.</small>
              </label>
            </div>
            <label>
              Допустимые CIDR
              <textarea
                required
                rows={2}
                value={rule.cidrs}
                onChange={(event) => update(index, "cidrs", event.target.value)}
                spellCheck={false}
                placeholder="10.20.0.0/24"
              />
              <small>
                Явные сетевые адреса через запятую или с новой строки, до 64 на
                правило. Для одного адреса используйте /32 или /128.
              </small>
            </label>
            <div>
              <button
                type="button"
                className="text-button danger-text"
                onClick={() =>
                  setRules((current) =>
                    current.filter((_, position) => index !== position),
                  )
                }
              >
                <Trash2 size={14} />
                Удалить правило {index + 1}
              </button>
            </div>
          </fieldset>
        ))}
        {!rules.length && (
          <Notice tone="warning">
            Нет правил: после сохранения все внешние подключения будут
            запрещены.
          </Notice>
        )}
        <div>
          <button
            type="button"
            className="button button-secondary"
            disabled={rules.length >= 128}
            onClick={() => setRules((current) => [...current, ruleDraft()])}
          >
            <Plus size={16} />
            Добавить правило
          </button>
        </div>
        <p className="small muted">
          Правила для реестров образов и баз данных задают только сетевые
          границы. Они не включают отсутствующие сканеры или интеграции.
        </p>
        <div className="modal-footer">
          <button
            type="button"
            className="button button-secondary"
            onClick={onCancel}
          >
            Закрыть без сохранения
          </button>
          <button type="submit" className="button button-primary">
            Просмотреть изменения
          </button>
        </div>
      </form>
    </section>
  );
}

type Pending = { rules: EgressRule[]; revision: number };

function AdminSettings({ onSaved }: { onSaved?: () => void }) {
  const resource = useResource<AdminSetup>("/admin/setup");
  const [policyEditor, setPolicyEditor] = useState(false);
  const [pending, setPending] = useState<Pending>();
  const [until, setUntil] = useState<string | null>();
  const [notice, setNotice] = useState<string>();
  const setup = resource.data;
  const editing = policyEditor;
  async function perform() {
    if (!pending || !setup) return;
    setNotice(undefined);
    await api<EgressPolicy>("/admin/egress-policy", {
      method: "PUT",
      body: { expected_revision: pending.revision, rules: pending.rules },
    });
    setPolicyEditor(false);
    setNotice(
      "Политика исходящих подключений сохранена. Личные учётные данные необходимо импортировать заново.",
    );
    setPending(undefined);
    resource.reload();
    onSaved?.();
  }
  return (
    <div className="settings-workspace">
      <div className="settings-toolbar">
        <p className="small muted">
          Только администратор · Изменения требуют подтверждения пароля
        </p>
        <button
          className="button button-secondary button-small"
          disabled={editing || resource.loading}
          onClick={() => {
            resource.reload();
          }}
        >
          <RefreshCw size={15} />
          Обновить настройки
        </button>
      </div>
      <ErrorBox
        message={resource.error}
        retry={editing ? undefined : resource.reload}
      />
      {resource.error && setup && (
        <Notice tone="warning">
          Показаны ранее загруженные данные. Закройте несохранённую форму и
          обновите настройки перед новым действием.
        </Notice>
      )}
      {resource.loading && <Spinner label="Загружаем настройки с сервера…" />}
      {setup && (
        <>
          {setup.legacy_configuration_available && (
            <Notice tone="warning">
              Найдена прежняя конфигурация развёртывания. Она не используется
              автоматически. Настройте политику исходящих подключений здесь либо
              попросите оператора выполнить явный импорт через командную строку.
            </Notice>
          )}
          {notice && <Notice tone="success">{notice}</Notice>}
          <Panel
            title="Исходящие подключения"
            action={
              <button
                className="button button-secondary button-small"
                disabled={editing || resource.loading || !!resource.error}
                onClick={() => {
                  setPolicyEditor(true);
                  setNotice(undefined);
                }}
              >
                <Network size={15} />
                Изменить политику
              </button>
            }
          >
            <div className="panel-body form-stack">
              <p className="small muted">
                Ревизия {setup.policy.revision} · Только явно разрешённые узлы,
                порт и CIDR. Сохранение не проверяет DNS или доступность сети.
              </p>
              <PolicyPreview rules={setup.policy.rules} />
            </div>
            {policyEditor && (
              <PolicyEditor
                key={setup.policy.revision}
                policy={setup.policy}
                onCancel={() => setPolicyEditor(false)}
                onPreview={(rules) =>
                  setPending({
                    rules,
                    revision: setup.policy.revision,
                  })
                }
              />
            )}
          </Panel>
        </>
      )}
      {pending && setup && (
        <AdminConfirmation
          title="Проверьте новую политику исходящих подключений"
          confirmLabel="Подтвердить и сохранить"
          initialUntil={until ?? setup.reauthenticated_until}
          onReauthenticated={setUntil}
          warning={policyWarning}
          onConfirm={perform}
          onClose={() => setPending(undefined)}
        >
          <div className="form-stack">
            <p className="small">
              Замена всей политики, исходная ревизия {pending.revision}.
              Удалённые из списка правила перестанут действовать.
            </p>
            <PolicyPreview rules={pending.rules} />
          </div>
        </AdminConfirmation>
      )}
    </div>
  );
}

export function SettingsPage({
  user,
  embedded = false,
  onSaved,
}: {
  user: User;
  embedded?: boolean;
  onSaved?: () => void;
}) {
  return (
    <>
      {!embedded && (
        <PageHeader
          title="Настройки подключений"
          description="Границы исходящих подключений AmberData. Сохранение не проверяет доступность сети."
        />
      )}
      {canManage(user.role) ? (
        <AdminSettings onSaved={onSaved} />
      ) : (
        <Notice>
          Настройки исходящих подключений доступны только администратору.
          Попросите администратора разрешить адреса Kubernetes API. Ваши личные
          учётные данные управляются в разделе «Кластеры».
        </Notice>
      )}
    </>
  );
}

export function SettingsModal({
  user,
  onClose,
  onSaved,
}: {
  user: User;
  onClose: () => void;
  onSaved: () => void;
}) {
  return (
    <Modal
      wide
      title="Настройки подключений"
      subtitle="Черновик kubeconfig остаётся в памяти мастера. Закройте это окно, чтобы продолжить подключение."
      onClose={onClose}
    >
      <SettingsPage user={user} embedded onSaved={onSaved} />
    </Modal>
  );
}
