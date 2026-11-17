import { useEffect, useState, type FormEvent } from "react";
import {
  Activity,
  ArrowRight,
  Boxes,
  ChevronRight,
  FileInput,
  Fingerprint,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  RefreshCw,
  ScanLine,
  ShieldCheck,
  Settings2,
  Sun,
  X,
} from "lucide-react";
import { api, ApiError, errorText, onUnauthorized, setSession } from "./api";
import { Brand, ErrorBox, Notice, Spinner } from "./ui";
import { roleLabels } from "./utils";
import { connectionDraftId } from "./namespaces";
import { OverviewPage, ModesPage, AuditPage } from "./pages/Overview";
import { ClustersPage } from "./pages/Clusters";
import { RunsPage } from "./pages/Runs";
import { FindingsPage } from "./pages/Findings";
import { ImportsPage } from "./pages/Imports";
import { SettingsPage } from "./pages/Settings";
import type { Page, Session } from "./types";

const navigation = [
  { id: "overview" as const, title: "Обзор", icon: LayoutDashboard },
  { id: "clusters" as const, title: "Кластеры", icon: Boxes },
  { id: "runs" as const, title: "Проверки", icon: ScanLine },
  { id: "findings" as const, title: "Находки", icon: ShieldCheck },
  { id: "imports" as const, title: "Импорт отчётов", icon: FileInput },
  { id: "modes" as const, title: "Возможности", icon: Activity },
  { id: "audit" as const, title: "Журнал действий", icon: Fingerprint },
  { id: "settings" as const, title: "Настройки", icon: Settings2 },
];

function Login({
  onLogin,
  initialError,
}: {
  onLogin: (session: Session) => void;
  initialError?: string;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const session = await api<Session>("/login", {
        method: "POST",
        body: { username, password },
      });
      setPassword("");
      setSession(session);
      onLogin(session);
    } catch (reason) {
      setError(errorText(reason));
      setPassword("");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-layout">
      <section className="login-story">
        <Brand />
        <div className="login-copy">
          <div className="scope-illustration" aria-hidden="true">
            <div className="scope-node scope-node-top">
              <Boxes size={30} />
            </div>
            <div className="scope-branch" />
            <div className="scope-bottom">
              <span />
              <span />
              <span />
            </div>
          </div>
          <h1>
            Безопасность начинается
            <br />с понимания границ.
          </h1>
          <p>
            Проверяйте конфигурацию Kubernetes, разбирайте доказательства и
            сохраняйте историю решений — в одном рабочем пространстве.
          </p>
          <div className="login-principles">
            <span>
              <ShieldCheck size={17} />
              Доступ только на чтение
            </span>
            <span>
              <Fingerprint size={17} />
              Проверяемые действия
            </span>
          </div>
        </div>
        <p className="login-footer">AmberData / Kubernetes Workbench</p>
      </section>
      <main className="login-main">
        <div className="login-form-wrap">
          <span className="login-section-label">
            Рабочее пространство аудита
          </span>
          <h2>Вход в консоль</h2>
          <p className="muted">
            Используйте локальную учётную запись, созданную администратором.
          </p>
          <ErrorBox message={error} />
          <form onSubmit={submit} className="form-stack">
            <label>
              Имя пользователя
              <input
                autoComplete="username"
                autoFocus
                required
                maxLength={100}
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
            </label>
            <label>
              Пароль
              <input
                type="password"
                autoComplete="current-password"
                required
                maxLength={256}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <button
              type="submit"
              className="button button-primary login-submit"
              disabled={busy}
            >
              {busy ? "Выполняется вход…" : "Войти в консоль"}
              <ArrowRight size={17} />
            </button>
          </form>
          <div className="login-help">
            <ShieldCheck size={19} />
            <p>
              Пароль и токены не сохраняются в хранилище браузера. Учётных
              записей и паролей по умолчанию нет.
            </p>
          </div>
        </div>
        <span className="login-main-footer">
          Kubernetes · Аудит конфигурации · Разбор находок
        </span>
      </main>
    </div>
  );
}

export function App() {
  const [session, updateSession] = useState<Session | null>(null);
  const [booting, setBooting] = useState(true);
  const [bootError, setBootError] = useState<string>();
  const [sessionNotice, setSessionNotice] = useState<string>();
  const [resumeDraftId, setResumeDraftId] = useState(() =>
    connectionDraftId(window.location.hash),
  );
  const [page, setPage] = useState<Page>(() =>
    connectionDraftId(window.location.hash) ? "clusters" : "overview",
  );
  useEffect(() => {
    const resume = () => {
      const id = connectionDraftId(window.location.hash);
      if (id) {
        setResumeDraftId(id);
        setPage("clusters");
      }
    };
    window.addEventListener("hashchange", resume);
    return () => window.removeEventListener("hashchange", resume);
  }, []);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [selectedRun, setSelectedRun] = useState<string>();
  const [theme, setTheme] = useState<"light" | "dark">(() =>
    window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light",
  );
  const [logoutError, setLogoutError] = useState<string>();
  const [loggingOut, setLoggingOut] = useState(false);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  useEffect(() => {
    onUnauthorized(() => {
      updateSession(null);
      setSessionNotice("Сессия завершена. Войдите снова, чтобы продолжить.");
    });
    return () => onUnauthorized(undefined);
  }, []);
  async function restore() {
    setBooting(true);
    setBootError(undefined);
    try {
      const value = await api<Session>("/session");
      setSession(value);
      updateSession(value);
    } catch (reason) {
      if (!(reason instanceof ApiError && reason.status === 401))
        setBootError(errorText(reason));
    } finally {
      setBooting(false);
    }
  }
  useEffect(() => {
    void restore();
  }, []);
  function navigate(next: Page) {
    setPage(next);
    setMobileOpen(false);
    setSelectedRun(undefined);
    document.getElementById("workspace-main")?.focus();
  }
  function openRun(id: string) {
    setPage("runs");
    setSelectedRun(id);
  }
  async function logout() {
    setLoggingOut(true);
    setLogoutError(undefined);
    try {
      await api("/logout", { method: "POST" });
      setSession(null);
      updateSession(null);
      setSessionNotice(undefined);
      setPage("overview");
    } catch (reason) {
      setLogoutError(errorText(reason));
    } finally {
      setLoggingOut(false);
    }
  }
  if (booting)
    return (
      <div className="boot-screen">
        <Brand />
        <Spinner label="Проверяем сессию…" />
      </div>
    );
  if (bootError && !session)
    return (
      <div className="boot-screen">
        <Brand />
        <div className="boot-error">
          <ErrorBox message={bootError} retry={() => void restore()} />
          <p className="muted">
            Для работы консоли необходим API. Демонстрационный режим не
            используется.
          </p>
        </div>
      </div>
    );
  if (!session)
    return (
      <Login
        key={sessionNotice}
        initialError={sessionNotice}
        onLogin={(value) => {
          updateSession(value);
          setSessionNotice(undefined);
          setPage(resumeDraftId ? "clusters" : "overview");
        }}
      />
    );
  const user = session.user;
  const title = navigation.find((item) => item.id === page)?.title;
  return (
    <div className="app-shell">
      <a href="#workspace-main" className="skip-link">
        Перейти к содержимому
      </a>
      {mobileOpen && (
        <button
          className="sidebar-overlay"
          aria-label="Закрыть навигацию"
          onClick={() => setMobileOpen(false)}
        />
      )}
      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
        <div className="sidebar-brand">
          <Brand />
          <button
            className="icon-button mobile-only"
            aria-label="Закрыть навигацию"
            onClick={() => setMobileOpen(false)}
          >
            <X size={20} />
          </button>
        </div>
        <div className="workspace-label">
          <span className="workspace-monogram">K8s</span>
          <div>
            <strong>Аудит безопасности</strong>
            <small>Рабочее пространство</small>
          </div>
        </div>
        <nav aria-label="Основная навигация">
          {navigation
            .filter(
              (item) => item.id !== "audit" || user.role === "administrator",
            )
            .map(({ id, title: label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => navigate(id)}
                className={`nav-item ${page === id ? "nav-item-active" : ""}`}
                aria-current={page === id ? "page" : undefined}
              >
                <Icon size={19} aria-hidden="true" />
                <span>{label}</span>
                {page === id && (
                  <ChevronRight size={15} className="nav-chevron" />
                )}
              </button>
            ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="readonly-note">
            <ShieldCheck size={17} />
            <div>
              Без изменения ресурсов<small>Проверка Kubernetes через GET</small>
            </div>
          </div>
          <div className="user-row">
            <div className="avatar" aria-hidden="true">
              {user.username.slice(0, 2).toLocaleUpperCase("ru")}
            </div>
            <div className="user-info">
              <strong title={user.username}>{user.username}</strong>
              <small>{roleLabels[user.role]}</small>
            </div>
            <button
              className="icon-button"
              aria-label="Выйти из учётной записи"
              title="Выйти"
              disabled={loggingOut}
              onClick={() => void logout()}
            >
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-only"
              aria-label="Открыть навигацию"
              aria-expanded={mobileOpen}
              onClick={() => setMobileOpen(true)}
            >
              <Menu size={21} />
            </button>
            <span>Консоль</span>
            <ChevronRight size={14} aria-hidden="true" />
            <strong>{title}</strong>
          </div>
          <div className="topbar-actions">
            <span className="session-label">
              <ShieldCheck size={15} />
              Локальная сессия
            </span>
            <button
              className="icon-button"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              aria-label={
                theme === "light"
                  ? "Включить тёмную тему"
                  : "Включить светлую тему"
              }
              title="Переключить тему"
            >
              {theme === "light" ? <Moon size={19} /> : <Sun size={19} />}
            </button>
          </div>
        </header>
        <main id="workspace-main" className="main-content" tabIndex={-1}>
          <ErrorBox message={logoutError} />
          {user.role === "viewer" && (
            <div className="role-notice">
              <Notice>
                Режим наблюдателя: просмотр доступных кластеров, проверок и
                находок. Запуск, импорт и экспорт недоступны. Права на каждый
                объект проверяет сервер.
              </Notice>
            </div>
          )}
          {page === "overview" && (
            <OverviewPage user={user} navigate={navigate} openRun={openRun} />
          )}
          {page === "clusters" && (
            <ClustersPage
              user={user}
              openRun={openRun}
              resumeDraftId={resumeDraftId}
              onResumeHandled={() => setResumeDraftId(undefined)}
            />
          )}
          {page === "runs" && (
            <RunsPage
              user={user}
              selectedRun={selectedRun}
              setSelectedRun={setSelectedRun}
            />
          )}
          {page === "findings" && (
            <FindingsPage user={user} openRun={openRun} />
          )}
          {page === "imports" && <ImportsPage user={user} openRun={openRun} />}
          {page === "modes" && <ModesPage />}
          {page === "settings" && <SettingsPage user={user} />}
          {page === "audit" && user.role === "administrator" && <AuditPage />}
        </main>
        <footer className="workspace-footer">
          <span>AmberData Kubernetes Workbench</span>
          <span>
            Покрытие отдельно от результатов · Время в локальном часовом поясе
          </span>
          <button
            className="text-button"
            onClick={() => window.location.reload()}
          >
            <RefreshCw size={12} />
            Обновить сессию
          </button>
        </footer>
      </div>
    </div>
  );
}
