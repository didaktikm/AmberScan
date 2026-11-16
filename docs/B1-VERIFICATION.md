# B1 / 0.2.0 — реализовано и проверено

Дата: 2026-11-16. Это отчёт о локальной проверке B1, **не приёмка всего MVP B** и не доказательство совместимости с реальными кластерами пользователя.

## Реализовано

- Административный UI/API OIDC providers и per-purpose/per-host/port/CIDR egress. DB-managed настройки, без обязательного ручного JSON и без restart при сохранении.
- Protected reauthentication, CSRF/RBAC, write-only encrypted client secret, отдельный IdP CA, явная проверка discovery/JWKS. Passive GET/save не делает DNS/сетевых обращений.
- Revision/generation fencing, post-exchange recheck, одноразовые session-bound credentials либо явно сохранённый personal ID token, личный и глобальный отзыв. Worker использует expiry своего immutable run snapshot.
- Сохранение kubeconfig draft только в памяти при переходе в Settings. Отдельные состояния empty/loading/error, безопасные сообщения, честные capability labels.
- Guarded Alembic upgrade 0.1→0.2, offline backup/restore с отдельным ключом, maintenance image. Runtime отклоняет неподходящие schema markers вместо ложного readiness.

## Выполненные проверки

| Проверка | Результат |
| --- | --- |
| Весь backend `pytest tests -q` | **590 passed**, 1 предупреждение Starlette о будущей замене httpx TestClient transport |
| `ty check src/workbench` | **PASS** |
| Frontend unit/interaction tests | **93 passed**, 255 assertions |
| Frontend TypeScript/production build | **PASS** |
| Docker runtime и maintenance build | **PASS** |
| Одноразовый Compose с настоящим PostgreSQL | **PASS**: fresh init, readiness, login/CSRF/logout, worker heartbeat, empty→reauth→policy/provider setup, restart persistence, повторный bootstrap |
| Настоящий browser smoke на одноразовом `127.0.0.1:18080` | **PASS**: login; provider preview/reauth/save; policy save; kubeconfig inspect и возврат из вложенных Settings с сохранённым draft; narrow dark layout; console errors не наблюдались |
| Отдельный PostgreSQL 17.5 recovery smoke | **PASS**: настоящий pg_dump→pg_restore 0.1 и 0.2, неверный ключ отклонён до restore, upgrade сохраняет users/ACL/history, legacy auth инвалидируется, provider secret восстанавливается с revision-bound AAD |
| Offline API→реальный OIDCProvider→fake HTTPS transport | **PASS**: реальный RSA-signed JWT, PKCE/verifier, nonce/audience, single-use callback, refresh discard |
| Негативные/race tests | **PASS**: provider/policy/revoke/logout/role/grant во время begin/exchange, stale generations, session-bound one-shot consumption, immutable expiry, worker stale owner/lease/result fencing |

Внутри проверок обнаружены и исправлены: stale ORM cache при повторном отзыве (generation не увеличивалась), некорректный тип enum приводил к 500, setup probe принимал непригодный JWKS, buffered archive descriptor нарушал начало pg_restore stdin. Для исправлений добавлены регрессии и повторены соответствующие проверки.

Lint: новые config/OIDC/migration/backup/test modules и изменённые импорты проверены. Полная строгая Ruff-проверка старых FastAPI handlers не заявляется чистой: часть прежних правил B008/FURB/BLE требует отдельного согласованного приведения стиля. Типы всего backend проверены.

## Что НЕ проверено / НЕ выполнено

- Вход через живой Keycloak или Dex и доступ к реальному Kubernetes. Browser smoke намеренно **не** нажимал Verify/Authorize, чтобы не обращаться к инфраструктуре.
- Реальные Kubescape/Trivy CLI, скачивание registry images/CVE DB, полноценный ScanProfile builder и runner isolation — следующая поставка B2.
- Два реальных disposable Kubernetes-кластера, полный browser scan E2E, PostgreSQL concurrency под нагрузкой — часть последующей приёмки.
- Восстановление текущей пользовательской БД. Проверено только синтетическое состояние в отдельных БД; нужен rehearsal собственного backup перед применением upgrade.
- Публикация образов, commit/push, production changes, изменения IdP, пользовательский kubeconfig/secret-файлы.
- Полный SBOM/license/security release audit, автоматическая ротация master key, schedules/refresh/team SSO/операторы/runtime.

## Состояние окружения

Тестовые Compose projects/БД/volumes создавались с уникальными именами и были удалены после тестов. Пользовательский запущенный экземпляр не перезапускался/не мигрировался, `.local` не читался и не изменялся. `power-motors` остался без изменений.

Read-only Docker labels показали, что текущие `deploy-api-1`/`deploy-worker-1` связаны с **другим** рабочим каталогом: `/Users/didaktik/Documents/antigravity/kubernetes-workbench/kubernetes-workbench/deploy`. Его исходники и конфигурация не обследовались и не изменялись. Новые файлы относятся только к `/Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench`; обновление другого экземпляра требует отдельного выбора целевого проекта и проверки совместимости, а не слепого применения этой миграции.

## Дальше

1. Выбрать целевой экземпляр для применения B1; воспользоваться [UPGRADE-B1.md](UPGRADE-B1.md) **только для совместимой исходной схемы этого проекта**.
2. Настроить фактические issuer/client/audience/CA и разрешённые назначения через UI локально, без передачи секретов в чат.
3. Реализовать B2: профили, настоящий offline scanner runner, управляемое OCI acquisition, checkpoints/evidence и process-group cleanup.
4. Закрыть B3 интеграционным lab/release acceptance; не называть MVP завершённым до этих проверок.
