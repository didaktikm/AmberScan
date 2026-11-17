# AmberData Kubernetes Security Workbench — kubeconfig-only / 0.5.3

Браузерный React UI, FastAPI API, PostgreSQL и отдельный worker. Единственный способ подключения Kubernetes — **self-contained kubeconfig с inline token или клиентским сертификатом/ключом**. Авторизация через внешних провайдеров, redirects и соответствующие настройки удалены из действующего приложения. Локальный вход Workbench остаётся отдельным от Kubernetes identity.

Сценарий: kubeconfig → явный context → список namespaces → галочки → GET-only preflight → сохранение. Нет web-terminal, фиктивных результатов или автоматически выданных Kubernetes прав. Это ещё не завершённый MVP: живые адаптеры Kubescape/Trivy не реализованы.

## Обновление существующей установки

**Не удаляйте `.local`, master key или PostgreSQL volume. Не запускайте `init-db` вместо миграции.** Для схем 0.1–0.4 требуется явное offline-обновление с backup и проверенным восстановлением в другую пустую БД. Порядок: [KUBECONFIG-AUTH.md](docs/KUBECONFIG-AUTH.md).

Сохраняются пользователи, подключения, allowlists, grants и история. Миграция отзывает личные Kubernetes credentials, отменяет queued и прерывает running работы. **После обновления повторно импортируйте kubeconfig в сохранённое подключение.** Это не отзыв токена/сертификата в Kubernetes. Изменение исходников не заменяет уже работающий Docker-образ.

Инструкция относится только к `/Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench`, Compose-проекту `amberdata-workbench`. Не применяйте её к соседним проектам с похожим интерфейсом.

## Новая установка на Mac

Нужны Docker Desktop и `uv`. Первая сборка скачивает базовые образы и зависимости, но не обращается к Kubernetes.

```bash
cd /Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench
export WORKBENCH_UID="$(id -u)" WORKBENCH_GID="$(id -g)"

# Только для новой установки: существующие secrets не перезаписываются.
PYTHONPATH=src uv run --frozen python -m workbench.setup_local

docker --context desktop-linux compose up -d --build --wait api worker

# Пароль задаётся интерактивно, без эха; пароля по умолчанию нет.
docker --context desktop-linux compose exec api python -m workbench.admin create-user admin --role administrator
```

Откройте **http://127.0.0.1:8080**. Не подменяйте адрес на `localhost`: Host/Origin соответствуют `public_origin`. PostgreSQL не публикует порт, API доступен только через loopback. Не используйте `sudo` и не делайте secret-файлы общедоступными.

`init-db` создаёт схему только в новой выделенной БД. Повторный запуск с текущей схемой сохраняет данные; старую схему он автоматически не обновляет.

## Подключение к кластеру

1. Администратор настраивает **«Настройки → Подключения»**: разрешающее правило Kubernetes с точным hostname, портом и CIDR. DNS-адреса должны соответствовать правилу этого назначения. Egress не создаётся из kubeconfig автоматически.
2. В «Кластерах» загрузите self-contained kubeconfig и выберите context. Поддерживаются `token` либо `client-certificate-data` + `client-key-data`. `exec`, `auth-provider`, внешние file paths, proxy, basic auth, impersonation и insecure TLS не поддерживаются.
3. Выберите личное хранение: по умолчанию на один запуск, ≤1 часа и не дольше web-сессии; явное повторное использование — ≤24 часов. Исходный срок credentials может сократить интервал.
4. Получите namespaces, отметьте нужные и выполните preflight. Начальный выбор пустой, новые страницы автоматически не выбираются. При запрещённом listing можно вручную ввести известные namespace. Сохранённый scope ограничен 100 именами.
5. Сохраните подключение. Для запуска выберите подмножество сохранённого scope. Одноразовые credentials расходуются при enqueue, не при discovery/preflight.

Credentials личные, зашифрованные, не передаются другим пользователям через grants. Исходный YAML не хранится. Не присылайте kubeconfig, токены и private keys в чат/issue/логи. При истечении доступа используйте повторный импорт для того же endpoint/CA/context. TLS/hostname/SNI, DNS pinning и сетевые ограничения не отключаются.

Подробности: [KUBECONFIG-AUTH.md](docs/KUBECONFIG-AUTH.md). Исторические схемы/миграции и offline проверка старых backups сохраняют описания прежнего формата исключительно для обновления и восстановления.

## Повторный запуск и остановка

```bash
export WORKBENCH_UID="$(id -u)" WORKBENCH_GID="$(id -g)"
docker --context desktop-linux compose up -d --wait api worker
docker --context desktop-linux compose ps

# Остановить приложение, оставив БД работающей:
docker --context desktop-linux compose stop api worker
```

Не используйте `down -v`. Не удаляйте `.local/master-key`: новый ключ не расшифрует старые данные. При смене порта согласованно измените `WORKBENCH_PORT` и deployment `public_origin` до запуска. Если secret-файлы недоступны, проверьте владельца/UID/GID, а не ослабляйте права до `0644`.

## Ограничения

- Живые Kubescape/Trivy не реализованы: доступны ограниченные встроенные read-only проверки и импорт поддерживаемых JSON-отчётов. См. [SCANNERS.md](docs/SCANNERS.md).
- Нет расписаний, автоматического refresh credentials, SSO приложения, runtime/operator-интеграций и автоисправлений.
- Чекбоксы ограничивают приложение, но не Kubernetes RBAC. Предпочтительна отдельная read-only identity.
- Application egress policy не заменяет сетевой firewall; Compose `outbound` сам по себе не фильтрует назначения.
- API/worker доверены общим master key/БД. PostgreSQL пилота использует владельца БД; для командной эксплуатации нужны отдельные runtime/migration роли.
- Автоматическое retention-удаление не реализовано. Offline backup/restore не означает HA/DR или гарантированное восстановление без rehearsal.
- Базовые образы закреплены версиями, не все digest. Нужны отдельные vulnerability/SBOM/license проверки перед production.
- Успех unit/mocked tests не доказывает доступ к конкретному кластеру: необходимы фактические TLS/auth/RBAC проверки из контейнерной сети.

## Разработка и проверки

Выполненные проверки, обновление Docker и оставшиеся ограничения: [KUBECONFIG-ONLY-VERIFICATION.md](docs/KUBECONFIG-ONLY-VERIFICATION.md).

```bash
PYTHONPATH=src uv run --frozen pytest tests -q
bun run --cwd frontend test
bun run --cwd frontend typecheck
bun run --cwd frontend build
PYTHONPATH=src uv run --frozen ty check src/workbench
uv run --frozen ruff check src tests
```

Изолированные проверки запускаются явно после сборки соответствующих образов:

```bash
PYTHONPATH=src uv run --frozen python tests/smoke_namespace_postgres.py \
  --maintenance-image amberdata-workbench-maintenance:0.5.3-local
PYTHONPATH=src uv run --frozen python tests/smoke_compose.py
```

PostgreSQL smoke использует собственные временные контейнеры. Compose smoke использует случайный проект, порт18080, временную учётную запись и отдельный volume; удаляет только собственный disposable stack, не `amberdata-workbench`.

Vite dev на5173 требует соответствующего `public_origin` backend. Origin/CSRF не отключать; штатный Compose обслуживает UI/API same-origin на8080.
