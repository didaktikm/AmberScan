# Возможности

Список отдаёт `GET /api/capabilities`. Поле `version` — номер приложения. Статус `available` значит, что действие можно вызвать. `not_implemented` сейчас только у `team_sso`.

Порядок карточек зафиксирован тестом `test_capabilities_publish_the_confirmed_actions`:

| id | Смысл | Кластер |
| --- | --- | --- |
| `read_only` | Разовый встроенный аудит выбранных namespace | не меняется, только GET |
| `imports` | JSON Trivy, kube-bench, Kubescape | не ходим в кластер; происхождение отчёта не проверяется |
| `live_scanners` | Запуск закреплённых файлов Kubescape и Trivy | не меняется. Нет бинарника — покрытие `not_checked`, не скачивание |
| `scheduled` | Явное расписание раз в сутки | только чтение. Нужна авторизация `days_30` |
| `extended` | Один временный под `registry.k8s.io/pause:3.10`, имя `amberscan-probe-` и 8 hex | после подтверждения под создаётся и удаляется. Не privileged, без capabilities, не root |
| `operator` | Фиксированный оператор `amberscan-operator` | после подтверждения. Без `WORKBENCH_OPERATOR_IMAGE` очередь не создаётся. Роль только get/list/watch, без secrets |
| `runtime` | Импорт JSON Falco или Tetragon | агент не ставится. Команды и вывод отбрасываются, остаются правило, приоритет и namespace |
| `continuous` | Повтор того же чтения не чаще чем раз в 6 часов | не меняется. Та же авторизация на 30 дней. Это не поток событий |
| `remediate` | Одна встроенная находка контроллера | после подтверждения меняет шаблон. Правила: `builtin:privileged`, `builtin:privilege-escalation`, `builtin:root-user`, `builtin:host-namespaces`. Виды: Deployment, StatefulSet, DaemonSet |
| `team_sso` | Единый вход в само приложение | не делать |

Ответ постановки в очередь всегда содержит `cluster_changed: false`: в момент HTTP кластер ещё не трогали. `changes_cluster: true` у extended, operator и remediate означает, что worker позже выполнит запись. `continuous` в очередь сканера не встаёт: пишется расписание `watch` и текст, что проверка только на чтение.

Живой сканер Trivy вызывается как `k8s` с `--disable-node-collector`, без оболочки, с очищенным окружением и kubeconfig во временном каталоге `0600`. Kubescape — `scan framework nsa`. kube-bench локально не запускается: проверка узла относится к расширенному режиму, а не к бинарнику на хосте.

Импорт отчёта и импорт runtime создают запуск сразу в разборе, без worker и без учётных данных кластера.
