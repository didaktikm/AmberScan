# Проверка и deployment kubeconfig-only — 0.5.0

Дата: 2026-11-16. Проект `/Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench`, Docker context `desktop-linux`, Compose `amberdata-workbench`.

## Выполнено

Из действующего backend и UI удалены OIDC-протокол, providers/settings, authorize/callback, redirects, manual metadata-only onboarding, provider columns/revisions и legacy `id_token` fallback. Удалена PyJWT dependency, сохранены Vault/cryptography/mTLS. Единственный Kubernetes auth_type — kubeconfig, inline token или certificate/key.

Сохранены локальный login/CSRF/session, admin reauthentication, egress/TLS/DNS pinning, личные credentials/expiry/storage consent, grants/generation/session fences, immutable scope, discovery pagination, selected-only preflight и восстановление через личный переимпорт. Старые схемы/revisions и offline проверка старых encrypted backups остаются исключительно для совместимости восстановления.

## Реальные результаты проверок

| Проверка | Результат |
|---|---|
| Backend до изменений | 1137 passed, 1 warning |
| Backend итоговый `pytest tests -q` | **1129 passed**, 1 warning, 227.88s |
| Frontend Bun | **128 passed**, 0 failed, 534 assertions |
| Frontend typecheck | PASS |
| Frontend production build | PASS |
| `ty check src/workbench` | PASS |
| Ruff correctness `E9,F63,F7,F82` | PASS |
| Полный Ruff | **НЕ ПРОШЁЛ: 62 замечания**, до изменений74 |
| Disposable PostgreSQL17, upgrade0.1/0.2/0.3/0.4→0.5 | PASS |
| Disposable pre/post upgrade backup/restore, schema constraints/old runtime refusal | PASS |
| Runtime и maintenance Docker build0.5 | PASS |
| Disposable Compose: readiness, UI200, login/session/CSRF/logout, reauth/egress, worker heartbeat, restart persistence | PASS |
| Проверка built image: version0.5, нет `workbench.oidc`/`jwt`, нет OIDC в frontend JS | PASS |
| Actual deployment schema0.4→0.5 | PASS после backup и реального restore rehearsal |
| Actual `/api/health/ready`, UI, worker heartbeat | ready; HTTP200; worker idle |
| Actual удалённый callback | JSON404, не SPA HTML |
| Browser E2E | **Не выполнен**: browser automation `debugger_unavailable`, затем target `not_found` |
| Реальный Kubernetes TLS/auth/RBAC preflight | **Ожидает пользовательского входа и переимпорта через UI** |

Разница числа тестов связана с удалением чисто OIDC-протокольных сценариев и добавлением kubeconfig-only/migration regressions. Смешанные тесты authorization/races/scope не удалялись целиком. Предупреждение pytest — существующий Starlette TestClient/httpx deprecation, не ошибка приложения.

Полный lint: B00834 (FastAPI Depends defaults), PLC041423 (fixture aliases), BLE0013 (worker exception boundaries), I0012 (frozen revisions0001/0002). Правила не отключались, frozen revisions ради форматирования не переписывались. Correctness subset не выдается за полный lint.

## Исправления, выявленные проверкой

- PostgreSQL smoke сначала упал на устаревшем `oidc_provider_id` в fixture текущей схемы; fixture исправлен, последующие прогоны прошли, включая новый maintenance0.5 image.
- Ревью обнаружило, что фильтрация старых policy rules до полной валидации могла превратить malformed deny-all policy в рабочую. Добавлена полная frozen validation всех старых правил **до** удаления obsolete purpose; regression rollback для duplicate IDs/endpoints, запрещённых hosts/CIDRs и повреждённых правил. Аналогичная защита применена к deployment ceiling.
- Новая миграция первоначально отклоняла допустимые registry/database-purpose правила. Исправлено: сохраняются все не-OIDC правила без расширения; пустой список остаётся deny-all.
- Повторное независимое read-only ревью подтвердило исправление обоих migration defects; targeted frontend/runtime review новых actionable regressions не обнаружил. Это не полная security/production-приёмка.

## Actual deployment и восстановление

Исходное состояние: API/worker0.4.0-local, schema0.4, один encrypted credential, queued/running работ нет. До остановки сохранены source snapshot и rollback image tags. API/worker остановлены, PostgreSQL и пользовательский volume сохранены.

Backup:
- `backups/pre-0.5-CZITGN.dump` — 67681bytes, mode0600;
- `backups/pre-0.5-CZITGN.dump.manifest.json` — mode0600;
- master key не включён в архив и не менялся.

Именно этот архив восстановлен с существующим ключом в отдельную пустую PostgreSQL БД `restore_check`: isolated `network:none`, shared container loopback, tmpfs data, без published ports/пользовательских volumes. Restore подтвердил schema0.4 и один encrypted value. На восстановленной копии успешно выполнена rehearsal0.5; только после этого upgrade применён к основной БД. Временный restore-контейнер удалён после проверки его task label.

Схема после обновления:0.5.0/revision0005_remove_oidc. Один сохранённый Kubernetes credential отозван согласно одобренному плану. Отсутствие encrypted values после миграции ожидаемо; исходный ключ проверен по backup до удаления credentials. Сохранены доступные metadata:1 пользователь,2 подключения,0 runs/findings. Старые worker rows остаются историческими; новый worker публикует idle heartbeat.

Запущенные образы:
- `amberdata-workbench:0.5.0-local` — `sha256:22df44304cc6857756a785c7f993ccba4a316e99f56de51e74a0795e0d4818ac`;
- `amberdata-workbench-maintenance:0.5.0-local` — `sha256:d63b66539d3191379a588562333631e5fe63decba3d0c6aa46a823f22655a6fa`.

API healthy на **http://127.0.0.1:8080**, PostgreSQL healthy, worker running с проверенным heartbeat. Пользовательские secrets не выводились, пароль не сбрасывался, обходная auth-сессия не создавалась. Соседние проекты не менялись, commit/push/publication не выполнялись.

## Что осталось для live Kubernetes

Пользователь выбрал выполнить через UI. Нужно войти, открыть сохранённое подключение, повторно импортировать kubeconfig того же endpoint/CA/context и выполнить preflight сохранённых namespaces. По результату отдельно подтвердить TLS/auth/RBAC либо диагностировать отказ. Успех deployment и self-contained импорт не являются доказательством живого подключения. Kubernetes ресурсы/RBAC/IdP не менялись, TLS/egress не ослаблялись.

## Откат

Сохранены:
- source snapshot `/Users/didaktik/Documents/antigravity/amberdata-kubernetes-workbench-source-rollback-CZITGN/source-before-0.5.tar.gz`;
- runtime `amberdata-workbench:rollback-pre-0.5-CZITGN` (`a9a3e685f12a…`);
- maintenance `amberdata-workbench-maintenance:rollback-pre-0.5-CZITGN` (`3fdeadcab846…`);
- проверенные backup+manifest, исходный master key отдельно.

Остановить новую версию, сохранить её БД, восстановить pre-upgrade архив в другую пустую БД и подключить matching старые images с исходным ключом. Не запускать0.4 на схеме0.5, не применять destructive downgrade и не удалять пользовательский volume. Изменения после backup автоматически не переносятся.
