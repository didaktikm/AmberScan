# HTTP API

Префикс `/api`. Тело JSON, лишние поля моделей запрещены (`extra=forbid`). Статическая оболочка UI — `GET /` и файлы из `web_dist_dir`. Неизвестный путь API не должен отдавать HTML оболочки.

Сессия нужна всем маршрутам, кроме `GET /api/health/live`, `GET /api/health/ready` и `POST /api/login`.

## Сессия и здоровье

- `GET /api/health/live` — `status`, `version`.
- `GET /api/health/ready` — база отвечает и читается. Без сессии.
- `POST /api/login`, `GET /api/session`, `POST /api/logout`.
- `GET /api/capabilities` — версия и карточки из [capabilities.md](capabilities.md).
- `GET /api/overview` — числа по видимым кластерам и пульс обработчиков.
- `GET /api/audit` — только администратор.

## Кластеры

- `GET /api/clusters` — готовые подключения, которые пользователь вправе видеть.
- `PATCH /api/clusters/{id}` — имя и окружение, только администратор.
- `DELETE /api/clusters/{id}` — локальное удаление, администратор и свежий reauth.
- `POST /api/kubeconfig/inspect` — разбор контекстов без сохранения, только администратор. `ca_data` в ответ не входит.
- `POST/GET /api/cluster-drafts`, `GET/DELETE /api/cluster-drafts/{id}` — свои черновики.
- `POST /api/cluster-drafts/{id}/finalize` — выбранные namespace и флаг `accept_partial`.
- `POST /api/clusters/{id}/credential` — заменить личные данные того же сервера, CA и контекста. Нужен `expected_access_revision`.
- `DELETE /api/clusters/{id}/authorization` — личный отзыв, роли сканирования.
- `DELETE /api/clusters/{id}/credential` — отзыв всех, reauth.
- `POST /api/clusters/{id}/namespaces/discover` — только имена. На готовом кластере не-администратор видит пересечение с сохранённым списком.
- `POST /api/clusters/{id}/preflight` и `POST .../scope/preflight` — GET по выбранным именам. Смена области требует reauth.
- `PATCH /api/clusters/{id}/scope` — сохранить новый список.
- `POST /api/clusters/{id}/schedule` — `kind`: `periodic`, `watch` или `off`, `confirm: true`.
- `POST /api/clusters/{id}/protected-action` — `action`: `live_scanner`, `extended`, `operator`, `remediate`, `continuous`; `confirm: true`. Для `remediate` нужен `finding_id` длиной 36.

## Запуски и находки

- `POST /api/runs` — инвентарь по подмножеству сохранённых namespace, таймаут 10–600 секунд.
- `GET /api/runs`, `GET /api/runs/{id}`, `POST /api/runs/{id}/cancel`, `GET /api/runs/{id}/report` — форматы `json`, `markdown`, `html`.
- `POST /api/imports` — `scanner`: `trivy`, `kube-bench`, `kubescape`.
- `POST /api/runtime-imports` — `source`: `falco` или `tetragon`.
- `GET /api/findings` — фильтры кластера, серьёзности и строки поиска не длиннее 200.
- `PATCH /api/findings/{id}` — смена `disposition` по роли.

## Администрирование

- `POST /api/admin/reauth`
- `GET /api/admin/setup` — текущая политика, без секретов.
- `PUT /api/admin/egress-policy` — полная замена правил и `expected_revision`. Пустой список запрещает все исходящие. Потолок `egress_ceiling` может только сузить правила.

Правило: точный host, порт, до 64 CIDR. Назначение `kubernetes` нужно до первого похода в кластер. Иначе ответы `configuration_required`.

## Команды офлайн

`python -m workbench.admin` не имеет веб-ручки настройки. Пароль `create-user` спрашивается дважды с tty и не принимается из argv. Команды: `init-db`, `status`, `upgrade` (по умолчанию только план), `backup`, `restore`, `import-legacy`, `create-user`, `grant`. Обновление живой базы — отдельное окно, с подтверждённым backup и остановленными API и worker. Это не делает pull request и не делает `down -v`.
