# Проверки

Юнит-тесты не доказывают сеть конкретного кластера. Они держат контракт: кто что видит, какие URL допустимы, что запись не происходит без подтверждённого source.

## Как запускать

Из корня репозитория. Интерпретатор — `.venv`, если он есть. `PYTHONPATH=src` обязателен.

```bash
PYTHONPATH=src uv run --frozen pytest tests -q --ignore=tests/smoke_compose.py --ignore=tests/smoke_migrations.py --ignore=tests/smoke_namespace_postgres.py
bun run --cwd frontend test
bun run --cwd frontend typecheck
uv run --frozen ruff check src tests
```

Три smoke-файла сами ходят в Docker и не входят в обычный прогон. `smoke_compose.py` поднимает свой проект и порт 18080, чужой стек не удаляет. `smoke_namespace_postgres.py` нужен уже собранный maintenance-образ. `smoke_migrations.py` исторический и ждёт старый тег образа.

## Бэкенд

| Файл | Что закрепляет |
| --- | --- |
| `test_api.py` | Сессия, CSRF, Origin, здоровье, возможности, гранты, запуск, импорт, переименование и удаление кластера, версия `0.5.4` |
| `test_api_connections.py` | Черновик, дубликат, discovery, preflight, финализация, смена области, 401 Kubernetes не разлогинивает приложение |
| `test_api_configuration.py` | Политика egress, reauth, нет маршрутов старого единого входа |
| `test_api_kubeconfig.py` | Разбор kubeconfig: token и сертификат проходят, exec и auth-provider — нет |
| `test_actions.py` | URL действий, под и оператор не privileged, исходник оператора без методов записи, патч только после UID, Trivy не пишет токен в вывод |
| `test_rollout.py` | Сроки хранения, расписание не тратит `days_30`, сканер ставится в очередь без похода в кластер, оператор без образа не ставится, чистка результатов локальная, runtime-импорт без команд |
| `test_worker_scope.py` | Снимок области, отказ чужих URL, чистка до блокировки запуска |
| `test_worker_auth.py`, `test_worker_kubeconfig.py` | Аренда и снимок kubeconfig |
| `test_security.py`, `test_security_credentials.py` | Vault, TLS, разбор учётных данных |
| `test_scanners.py` | Разбор фикстур отчётов в `tests/fixtures/scanners/` |
| `test_namespaces.py` | Форма scope и URL инвентаря |
| `test_configuration.py` | Правила egress и потолок |
| `test_migrations.py`, `test_namespace_migrations.py`, `test_kubeconfig_migrations.py`, `test_remove_oidc_migrations.py`, `test_admin_migrations.py` | Замороженные схемы и отказ молчаливого обновления |
| `test_backup.py` | Дамп, ключ, отказ чужой версии схемы |
| `test_bootstrap.py` | Пустая база и отказ чужого маркера |
| `test_release_version.py` | Теги образов равны `__version__` |

Фикстуры HTTP в тестах API — `Mock`. Неожиданный `get_json` должен падать, а не ходить в сеть.

## Фронтенд

`frontend/tests/settings-interactions.test.tsx` — основной сценарий на happy-dom: политика, мастер, черновик, кнопки над списком кластеров, смена области. `ui.test.tsx` и `settings.test.tsx` — разметка и подписи. `api.test.ts` — клиент. `namespaces.test.tsx` и `namespace-layout.test.tsx` — выбор имён. `browser-layout/` — отдельный прогон вёрстки, не часть `bun test` по умолчанию.

Тексты кнопок сравниваются целиком. Новая подпись ломает тест, если он ищет старую строку. После правки экрана добавьте ожидание в этот файл и откройте собранное или живое приложение.
