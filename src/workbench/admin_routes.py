"""Explicit administrator setup; reads are passive, probes require recent reauth."""

from datetime import timedelta

from fastapi import Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from workbench.configuration import (
    policy_view,
    save_policy,
)
from workbench.db import (
    User,
    WebSession,
    audit,
    aware,
    iso,
    now,
)
from workbench.domain import DomainError
from workbench.security import password_verify

REAUTH_WINDOW = timedelta(minutes=5)


class Reauthentication(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    password: str = Field(min_length=1, max_length=256)


def reauthenticated_until(web_session) -> str | None:
    if web_session.reauthenticated_at is None:
        return None
    return iso(
        min(
            aware(web_session.reauthenticated_at) + REAUTH_WINDOW,
            aware(web_session.expires_at),
        )
    )


def require_admin(user) -> None:
    if user.role != "administrator":
        raise DomainError("Недостаточно прав приложения", "forbidden")


def require_recent_reauth(request, user) -> None:
    require_admin(user)
    web_session = request.state.web_session
    if (
        web_session.reauthenticated_at is None
        or aware(web_session.reauthenticated_at) + REAUTH_WINDOW <= now()
    ):
        raise DomainError(
            "Подтвердите пароль администратора перед изменением настроек",
            "reauthentication_required",
        )


def install_admin_routes(app, settings, vault, db, identity) -> None:
    @app.post("/api/admin/reauth")
    def reauthenticate(
        payload: Reauthentication,
        request: Request,
        user=Depends(identity),
        session=Depends(db),
    ):
        require_admin(user)
        user = session.scalar(
            select(User)
            .where(User.id == user.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if not user or not user.active:
            raise DomainError("Войдите в приложение", "unauthenticated")
        require_admin(user)
        if user.locked_until and aware(user.locked_until) > now():
            raise DomainError("Слишком много попыток. Повторите позже", "rate_limited")
        web_session = session.scalar(
            select(WebSession)
            .where(WebSession.token_hash == request.state.web_session.token_hash)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if not web_session or aware(web_session.expires_at) <= now():
            raise DomainError("Сессия истекла", "unauthenticated")
        if not password_verify(payload.password, user.password_hash):
            # A failed confirmation removes any prior elevation and shares login lockout.
            web_session.reauthenticated_at = None
            user.failed_logins += 1
            if user.failed_logins >= 5:
                user.failed_logins, user.locked_until = 0, now() + REAUTH_WINDOW
            audit(session, user.username, "reauthentication_failed", user.id)
            session.commit()
            raise DomainError("Пароль не подтверждён", "reauthentication_failed")
        user.failed_logins, user.locked_until = 0, None
        web_session.reauthenticated_at = now()
        audit(session, user.username, "reauthenticated", user.id)
        session.commit()
        return {"reauthenticated_until": reauthenticated_until(web_session)}

    @app.get("/api/admin/setup")
    def setup(request: Request, user=Depends(identity), session=Depends(db)):
        require_admin(user)
        return {
            "policy": policy_view(session),
            "reauthenticated_until": reauthenticated_until(request.state.web_session),
            "legacy_configuration_available": bool(
                settings.allowed_hosts or settings.allowed_cidrs
            ),
        }

    @app.put("/api/admin/egress-policy")
    def update_policy(
        payload: dict, request: Request, user=Depends(identity), session=Depends(db)
    ):
        require_recent_reauth(request, user)
        result = save_policy(session, payload, settings, user.username)
        session.commit()
        return result
