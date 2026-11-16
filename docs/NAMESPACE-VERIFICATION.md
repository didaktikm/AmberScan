# Выбор namespaces / 0.3.0 — результаты проверки

Дата: 16 ноября 2026. Проект: `amberdata-kubernetes-workbench`.

Реализация завершена в исходном коде. Рабочая установка пользователя не обновлялась. Это namespace onboarding поверх B1, **не готовность B2 и не production-приёмка**.

## Реализовано

- Собственный metadata-only draft: kubeconfig/context или ручные endpoint/context/CA, затем личная OIDC-авторизация и безопасное восстановление мастера после callback.
- Отдельное read-only обнаружение namespaces с ограничениями: 200 на страницу, максимум 5 страниц/1000 имён, общий deadline 30 секунд. Читается только NamespaceList; workloads discovery не обследует.
- Основной checkbox picker: пустой начальный выбор, поиск/счётчики/all/filtered/clear, системные метки, context hint, ручной ввод, сохранение выбора при обновлении, явные missing/incomplete/stale состояния.
- Selected-only GET preflight; 403 допускает явное принятие частичного покрытия только при наличии успешных probes. 401, TLS/DNS/сеть/egress не превращаются в пустой список или успешную проверку.
- Finalize с повторным серверным preflight; версия доступа и точный credential проверяются до/после запросов и при сохранении. Чужой draft/credential не становится общим.
- Редактирование сохранённой области с admin reauth, CAS, отзывом прежней авторизации и отменой устаревших заданий.
- Backend/worker enforce explicit subset. Run.scope имеет inventory_version=1 и копию в зашифрованном snapshot; HTTP сборщика ограничен точными namespaced URL текущего inventory. Новые namespaces не включаются автоматически.
- Схема 0.3.0/Alembic `0003_namespace_selection`, совместимые offline upgrade/backup/restore для проверенных 0.1/0.2/0.3 схем. Старые схемы/миграции frozen.

## Выполненные проверки

| Проверка | Результат |
|---|---|
| Исходный backend до изменений | 590 passed |
| Финальный `PYTHONPATH=src uv run --frozen pytest -q` | **999 passed**, одно предупреждение Starlette/httpx |
| `bun run --cwd frontend test` | **134 passed**, 447 assertions, 0 failed |
| `bun run --cwd frontend typecheck` | **PASS** |
| `bun run --cwd frontend build` | **PASS**, TypeScript + Vite production bundle |
| `uv run --frozen ty check src --output-format concise` | **PASS** |
| Ruff correctness: `--select E4,E7,E9,F` для `src tests` | **PASS** |
| `uv lock --check --offline` | **PASS**, версии согласованы, зависимости не обновлялись |
| YAML parse `compose.yaml`, `compose.maintenance.yaml` | **PASS**, без чтения `.local` и обращения к рабочим сервисам |
| Disposable PostgreSQL fresh schema/runtime markers | **PASS** |
| Disposable PostgreSQL 0.1 → 0.3 и 0.2 → 0.3 | **PASS**, allowlists/история/настройки B1 сохранены, устаревшая очередь очищена |
| PostgreSQL backup/restore до и после каждого upgrade | **PASS**, включая manifest/key validation и strict schema verification |
| PostgreSQL locked-draft cleanup/finalize | **PASS**, очистка пропускает заблокированный draft и не удаляет ready после завершения |
| PostgreSQL identity NO KEY UPDATE / FK KEY SHARE | **PASS**, проверена совместимость блокировки и конкурентной FK-вставки |

PostgreSQL smoke: `PYTHONPATH=src uv run --frozen python tests/smoke_namespace_postgres.py`. Использовались закэшированные PostgreSQL 17.5 и maintenance runtime 0.2.0 **с read-only mount текущего исходного кода 0.3.0**. БД только tmpfs, `network:none`, без published ports/пользовательских volumes/`.local`. Все контейнеры smoke удалены; проверка по специальной label не обнаружила оставшихся контейнеров.

Во время разработки обнаружены и исправлены ошибки самого smoke harness: путь монтированного скрипта и порядок flush синтетического FK-владельца. Последний полный smoke прошёл. Исходный вызов pytest без `PYTHONPATH=src` не собирал пакет; выше указан корректный штатный вызов, проходящий весь набор.

### Ограничение lint

Полный `ruff check src tests` с имеющимся широким профилем **не чистый**: 68 замечаний против 56 исходных. Категории: B008 (FastAPI Depends в сигнатурах), PLC0414 (явный импорт pytest fixtures), BLE001 (защитные catch в worker), I001 (исторические/незатронутые импорты), FURB162. Новые routes/fixtures продолжают существующий стиль, поэтому количество не равно исходному. Эта работа не включает общий lint-рефакторинг или ослабление настроек. Проверки correctness и source typing выше прошли; полный профиль не объявляется прошедшим.

## Исправления, найденные при проверке

- Namespace hint вне allowlist не выдаётся nonadmin через общий cluster view.
- Проверяются не только auth revisions, но и точная попытка credential: устаревший ответ не отменяет новую авторизацию.
- Отзыв/изменение доступа между GET-запросами и перед публикацией останавливает текущую операцию.
- Worker cleanup разделён на транзакции: каскадная очистка draft/auth завершается до блокировок Run; это устраняет выявленную обратную последовательность recovery/revoke.
- Identity locks в probe/callback/login/draft creation не конфликтуют с FK KEY SHARE при постановке задания/создании binding. Проверены SQL intent и отдельный PostgreSQL-сценарий; это не доказательство отсутствия всех возможных deadlocks под нагрузкой.
- UI учитывает устаревшие async-ответы, изменение scope/auth, неполный discovery и необходимость повторной OIDC при Kubernetes 401.

## Что не выполнялось

- Реальные Keycloak/Dex/Kubernetes запросы и приёмка с реальными RBAC/issuer/audience/claims.
- Browser E2E/визуальная приёмка с работающим приложением; UI проверен Bun/happy-dom, typecheck и сборкой.
- Сборка/публикация нового Docker runtime image и обновление рабочего Compose.
- Миграция текущей пользовательской БД, изменение production/IdP, соседних проектов или секретов.
- Полный нагрузочный/HA/DR-аудит, все конкурентные комбинации PostgreSQL.
- Кластерные scanner checks, живые Kubescape/Trivy, B2 profiles, schedules и runtime monitoring.

## Внедрение и откат

Для существующей установки нужен явный offline upgrade после backup и остановки API/worker. Изменение `POST /api/clusters`: прежний payload теперь создаёт draft; нужен finalize, готовые старые подключения сохраняются как ready. Не запускайте `init-db` или старый бинарник в обход schema gate.

Актуальные инструкции: [NAMESPACE-SELECTION.md](NAMESPACE-SELECTION.md). Откат — сохранённый pre-upgrade backup в отдельную пустую БД с прежним master key и соответствующей прежней версией. Destructive downgrade не реализован.
