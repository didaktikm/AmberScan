# Архитектура

AmberScan — локальный пульт аудита Kubernetes. Браузер говорит только с API. API не ходит в кластер во время обычного запроса списка. Живые запросы к API Kubernetes делает worker из снимка учётных данных, зашифрованного в строке запуска.

```
браузер (React, same-origin)
    → API FastAPI, cookie-сессия
        → PostgreSQL
    worker
        → расшифровка снимка запуска
        → PolicyHTTP: DNS pin, TLS, allowlist
        → Kubernetes API
```

Исходники бэкенда: `src/workbench/`. Сборка UI: `frontend/`. Образ копирует `frontend/dist` внутрь и отдаёт его тем же процессом API. Отдельного публичного фронтенд-сервера в Compose нет.

## Процессы Compose

Файл `compose.yaml`, проект на проверочной машине — `amberscan-smoke`. Имя в файле — `amberdata-workbench`; на Mac в инструкции README используется контекст `desktop-linux` и проект по имени файла.

| Сервис | Образ | Назначение |
| --- | --- | --- |
| `db` | `postgres:17.5-bookworm` | Только сеть `database`, порт наружу не публикуется |
| `init-db` | тот же runtime-образ | `python -m workbench.admin init-db`. Пустая база получает схему 0.5.0. Уже верная схема не меняется. Старая схема не обновляется этим сервисом |
| `api` | `amberdata-workbench:<версия>-local` | Uvicorn, фабрика `workbench.api:create_app`, порт контейнера 8080, снаружи только loopback |
| `worker` | тот же образ | `python -m workbench.worker` |
| `maintenance` | `amberdata-workbench-maintenance:<версия>-local` | Профиль `maintenance`, `compose.maintenance.yaml`. Это `python -m workbench.admin`, не веб |

Контейнеры приложения: `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, пользователь `WORKBENCH_UID:WORKBENCH_GID`. Секреты — bind mode `0600` из `.local`. Владелец файлов должен совпадать с UID контейнера, иначе чтение секрета падает: `CAP_DAC_OVERRIDE` снят.

Сети: `database` внутренняя (API, worker, Postgres), `outbound` у API и worker для Kubernetes. Политика приложения не заменяет внешний firewall.

## Конфигурация

`Settings.from_env` в `src/workbench/config.py`.

- `WORKBENCH_DATABASE_URL_FILE` — строка `postgresql+psycopg://...`. В тестах URL SQLite передаётся в конструктор напрямую.
- `WORKBENCH_MASTER_KEY_FILE` — urlsafe-base64 32 байт. Им шифруется Vault. Новый ключ не читает старые данные.
- `WORKBENCH_CONFIG_FILE` — JSON: `public_origin`, `allowed_hosts`, `allowed_cidrs`, `retention_days`, необязательный `egress_ceiling`.
- `WEB_DIST_DIR` — каталог собранного UI, в образе `/app/frontend/dist`.
- `WORKBENCH_TRIVY_BIN`, `WORKBENCH_KUBESCAPE_BIN`, `WORKBENCH_OPERATOR_IMAGE` — необязательны.

`public_origin` обязан быть `https` либо `http` только на loopback, без пути, пользователя и query. Браузер должен открывать тот же host: `localhost` вместо `127.0.0.1` ломает проверку Host/Origin.

Локальные файлы создаёт `python -m workbench.setup_local`. Существующий полный набор не перезаписывается. Неполный или с правами шире `0600` — ошибка, файлы не трогаются.

## Границы кода

| Модуль | Роль |
| --- | --- |
| `api.py` | HTTP, сессия, CSRF, маршруты. Сканеры здесь не запускаются |
| `admin_routes.py` | Повторный вход администратора и политика исходящих подключений |
| `admin.py` | Офлайн CLI: init, upgrade, backup, restore, create-user, grant |
| `services.py` | Кто видит кластер, вид запуска и находки, сохранение результата |
| `connections.py` | Черновики, проба GET без удержания блокировки на время сети, правка имени, удаление локального подключения |
| `security.py` | Пароли, Vault, разбор kubeconfig, TLS, DNS pin |
| `configuration.py` | Политика egress, `PolicyHTTP`, отзыв поколений доступа |
| `namespaces.py` | Версия области `inventory_version`, allowlist URL инвентаризации |
| `scanners.py` | Встроенный инвентарь и разбор JSON Trivy, kube-bench, Kubescape |
| `actions.py` | Подтверждённые режимы: живые сканеры, пробный под, оператор, исправление |
| `operator.py` | Текст цикла оператора: только GET списка namespace |
| `rollout.py` | Срок хранения учётных данных, расписание, локальная чистка результатов, импорт Falco/Tetragon |
| `worker.py` | Очередь, аренда, дочерний процесс сбора |
| `migrations.py` | Замороженные схемы 0.1–0.5 и сторож рантайма |
| `db.py` | Модели SQLAlchemy и `audit()` |
| `backup.py` | Дамп PostgreSQL и проверка ключа |

Блокировки, если нужны вместе: сначала политика (`lock_policy`), затем кластер, затем binding. Сетевой ввод-вывод не держит транзакцию. После ответа Kubernetes снимок запуска сверяется снова, и только потом результат пишется.

## Ошибки

`DomainError(message, code)` в `domain.py`. Карта кодов на HTTP — в обработчике `api.py`: `not_found` 404, `forbidden` и `reauthentication_required` 403, `unauthenticated` 401, `conflict` и `configuration_required` 409, `rate_limited` 429, прочее 400. Ошибки валидации Pydantic всегда одно сообщение `invalid_input` и статус 422, без эха полей. Ошибки SQLAlchemy — `storage_error` 503.
