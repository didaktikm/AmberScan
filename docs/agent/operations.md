# Сборка и проверочный стек

## Образы

`Dockerfile` многостадийный. Последняя стадия `runtime` — то, что попадает в тег `amberdata-workbench:<версия>-local`. Стадия `maintenance` — тег `amberdata-workbench-maintenance:<версия>-local` и клиент PostgreSQL 17.5. Аргумент `APP_VERSION` пишется в метку `org.opencontainers.image.version`.

Смена исходников не обновляет уже запущенный контейнер. Нужны новый тег, сборка и пересоздание API и worker.

На проверочной машине проект Compose называется `amberscan-smoke`, API — `http://127.0.0.1:8080`. Каталог `.local` и том `database-data` не удалять. `down -v` запрещён. `init-db` на базе, где уже есть пользователи и подключения, вручную не запускать. Если Compose сам повторит сервис `init-db` на схеме 0.5.0, `init_database` выйдет без изменений.

Проверка после перезапуска:

```bash
curl -sS http://127.0.0.1:8080/api/health/ready
curl -sS http://127.0.0.1:8080/api/health/live
```

Второй ответ содержит номер приложения. Образ контейнера API должен быть `amberdata-workbench:` плюс тот же номер.

Учётная запись создаётся интерактивно внутри API:

```bash
docker compose -p amberscan-smoke exec api python -m workbench.admin create-user admin --role administrator
```

Пароль не передаётся аргументом. Пароля по умолчанию в образе нет.

## Mac

Инструкция корневого README относится к checkout `/Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench` и контексту Docker `desktop-linux`. Это не проверочная машина. Команды оттуда не применять к соседним Compose-проектам.

## Что лежит рядом и зачем

- `.local/` — секреты машины, в git не входит.
- `tests/fixtures/scanners/` — JSON отчётов для разбора без кластера.
- `src/workbench/alembic/schema_v01.py` … `schema_v05.py` — замороженные формы. Их не «улучшают» задним числом.
- `src/workbench/alembic/versions/0001_baseline.py` … `0005_remove_oidc.py` — цепочка миграций. Новая ревизия нужна только если меняется схема, и тогда меняется `SCHEMA_VERSION`.
- `docs/KUBECONFIG-AUTH.md` — как оператору обновлять уже стоящую базу 0.1–0.4.
- `docs/SCANNERS.md` — формат импортируемых отчётов. Поведение живого запуска смотрите в [worker.md](worker.md), а не только там.
