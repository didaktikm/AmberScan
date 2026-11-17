# Проверка kubeconfig authentication — 0.4.0

Исторический отчёт, не приёмка0.5. При новом read-only осмотре Docker16.11.2026 до изменений0.5 обнаружены API/worker `0.4.0-local`, не0.3; раздел ниже фиксирует более раннее наблюдение, а не актуальное состояние deployment. Текущий контракт: [KUBECONFIG-ONLY-CONTRACT.md](KUBECONFIG-ONLY-CONTRACT.md).

Дата: 2026-11-16. Проверки выполнены в `amberdata-kubernetes-workbench`; настоящий kubeconfig, Kubernetes/IdP и пользовательская БД не использовались. Коммит/публикация и обновление работающего Compose не выполнялись.

## Результаты

| Проверка | Результат |
|---|---|
| `PYTHONPATH=src uv run --frozen pytest tests -q` | **1133 passed**, 1 предупреждение, 205.94 s (итоговый прогон после transport fix) |
| `PYTHONPATH=src uv run --frozen pytest tests/test_api_kubeconfig.py -q` (после последних дополнений) | **30 passed**, 1 предупреждение |
| `bun run --cwd frontend test` | **146 pass**, 0 fail, 554 assertions |
| `bun run --cwd frontend typecheck` | **PASS** |
| `bun run --cwd frontend build` | **PASS**, production bundle собран |
| `PYTHONPATH=src uv run --frozen ty check src/workbench` | **PASS** |
| `PYTHONPATH=src uv run --frozen ruff check --isolated --select E9,F63,F7,F82 src tests` | **PASS** |
| Disposable PostgreSQL17 upgrade/backup/restore smoke | **PASS**, подробности ниже |
| Compose YAML, согласованность image tags0.4 и `/tmp` tmpfs (без загрузки secrets) | **PASS** |

Первый полный прогон обнаружил 4 устаревших exact-shape assertions (поле normalized auth вместо id_token и новое поле continuation). Они обновлены под новый контракт; повторный полный прогон прошёл. Найденные при общей проверке типов два места без явного сужения optional/union в DraftInput исправлены, общий ty проходит.

Предупреждение pytest: Starlette сообщает о deprecated использовании `httpx` в TestClient и рекомендует `httpx2`. Это не скрыто как ошибка приложения и не повод менять dependencies вне текущего объёма.

### Полный lint — не чистый

`uv run --frozen ruff check src tests --statistics` возвращает **74 замечания**: B00843, PLC041423, I0014, BLE0013, FURB1621. Применяется существующий широкий профиль окружения: FastAPI Depends в сигнатурах, явные aliases pytest fixtures, защитные catch и исторические импорты. Correctness subset выше проходит; полный профиль **не объявляется прошедшим**. Массовый style-рефакторинг или ослабление правил не выполнялись.

## Покрытые сценарии

- Providerless fixtures с пустыми `settings.providers` и таблицей OIDC providers: token и client-certificate onboarding → discovery → selected-only preflight → finalize → enqueue.
- Worker token/cert: отсутствие текущего credential после one-shot enqueue не мешает immutable run snapshot; правильный Bearer или mTLS без Bearer; проверка policy/generation/grant/expiry/auth_type; публикация и очистка snapshots.
- Нормализация и изоляция: извлечение только выбранного context; metadata-only public inspect; никаких uploaded exec, путей к файлам, basic/proxy/insecure TLS; повреждённый auth не переключается на legacy fallback.
- Cert/key: соответствие ключа, validity, EKU/key usage и допустимые форматы; защищённые временные файлы и cleanup при успехе и ошибках.
- **Реальный OpenSSL mTLS handshake через MemoryBIO**, без сетевых соединений: успешный обмен и отказ при неверных CA/hostname/client trust/отсутствии client certificate. Это проверяет TLS-механику, но не совместимость с реальным k3s endpoint.
- Reimport: endpoint/CA/context consistency, CAS, отзыв прежнего личного поколения/работ, приватность user/session, expiry и ограничения хранения; отказ не оставляет частично созданные записи.
- Namespace batches >1000 имён: identity/session/credential/config/revision/snapshot-bound encrypted continuation, tamper/expiry/mismatch, 403/manual fallback, Kubernetes401 отдельно от web401. Идемпотентный повтор чтения того же snapshot допустим; UI не дублирует имена.
- UI без провайдеров: token/cert импорт без `/authorize`, пустой первоначальный checkbox selection, загрузка следующих страниц без автоматического выбора, лимит100 выбранных, восстановление после истечения snapshot; повторный импорт из draft/detail/run/scope. OIDC/manual сценарии сохранены.

## PostgreSQL и восстановление

Запущен `tests/smoke_namespace_postgres.py` с cached `postgres:17.5-bookworm` и `amberdata-workbench-maintenance:0.3.0-local` как средой зависимостей; **текущий** исходный код подключён read-only. Собственные случайно именованные помеченные контейнеры, изолированный network namespace (`network:none` + общий loopback), tmpfs-БД, без published ports и пользовательских volumes. Контейнеры удалены скриптом.

Проверены:
- fresh schema0.4;
- upgrade0.1/0.2/0.3 →0.4;
- сохранение scopes, history, grants и инвалидирование старых credentials/flows/work;
- backup/restore до и после миграции, включая normalized providerless encrypted credential;
- точная проверка CHECK constraints, отказ NOT VALID/NO INHERIT;
- несовместимость предыдущих runtime schema constants;
- существующие lock-сценарии.

SQLite — только тестовая среда: проверены parent-table rebuild без CASCADE-потери, rollback, foreign_key_check и восстановление enforcement. Старые frozen schemas не переписаны.

## Ограничение независимого ревью

Дополнительное ревью не завершило независимую проверку всего нового auth/UI-пути; его нельзя считать отдельным подтверждением корректности поверх тестов. Статически отмечены требующие отдельного воспроизведения прежние вопросы: гонка cancel/complete, polling медленных ответов, память при чтении findings и параллельной проверке паролей, распространение deadline preflight. Они не установлены как регрессии0.4 и не исправлялись в этой задаче. Замечание к EOF HTTP transport **подтверждено и исправлено**: при `Connection: close` прочитанный Content-Length закрывал сокет, а следующий `settimeout` превращал корректный JSON-ответ в `http_transport`. Добавлен regression с настоящим `HTTPResponse` и test-owned refcount socket без сети; цикл завершается по прочитанному Content-Length до повторного обращения к закрытому сокету. Проверки deadline, размеров, усечённого ответа и JSON сохранены.

## Не выполнялось

- Обновление пользовательских контейнеров или пользовательской БД. Последний `docker ps` показывает прежние API/worker **`amberdata-workbench:0.3.0-local`**.
- Сборка/приёмка нового runtime Docker image и browser E2E на работающем приложении. UI проверен happy-dom, typecheck и production-сборкой frontend.
- Live Kubernetes/k3s, Keycloak/Dex, реальные credentials/RBAC, production-нагрузка и отказоустойчивость.

Чтобы исправление появилось в уже открытом UI, требуется отдельное согласованное обновление Docker image и схемы с backup/restore-проверкой. Порядок и откат — [KUBECONFIG-AUTH.md](KUBECONFIG-AUTH.md). Простое обновление страницы не заменяет старый серверный образ.
