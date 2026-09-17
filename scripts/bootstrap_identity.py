#!/usr/bin/env python3
"""Bootstrap governado do primeiro tenant, usuário e membership.

Por padrão executa somente preview. Escrita exige simultaneamente:
  --apply
  --confirm APPLY_BOOTSTRAP

O script nunca imprime DATABASE_URL, senha ou segredo OIDC.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from orkio_v2.database import SessionLocal
from orkio_v2.models import Membership, Tenant, User


@dataclass(frozen=True)
class BootstrapPlan:
    tenant_id: str
    tenant_name: str
    user_id: str
    external_subject: str
    email: str
    display_name: str
    role: str
    create_tenant: bool
    create_user: bool
    create_membership: bool


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("--tenant-id", required=True)
    value.add_argument("--tenant-name", required=True)
    value.add_argument("--user-id", required=True)
    value.add_argument("--external-subject", required=True)
    value.add_argument("--email", required=True)
    value.add_argument("--display-name", required=True)
    value.add_argument("--role", default="admin")
    value.add_argument("--apply", action="store_true")
    value.add_argument("--confirm", default="")
    return value


def build_plan(db: Session, args: argparse.Namespace) -> BootstrapPlan:
    tenant = db.get(Tenant, args.tenant_id)
    user = db.get(User, args.user_id)
    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_id == args.tenant_id,
            Membership.user_id == args.user_id,
        )
    )

    if tenant and tenant.name != args.tenant_name:
        raise RuntimeError("TENANT_CONFLICT")
    if user and (
        user.external_subject != args.external_subject
        or user.email.lower() != args.email.lower()
    ):
        raise RuntimeError("USER_CONFLICT")
    if membership and membership.role != args.role:
        raise RuntimeError("MEMBERSHIP_CONFLICT")

    return BootstrapPlan(
        tenant_id=args.tenant_id,
        tenant_name=args.tenant_name,
        user_id=args.user_id,
        external_subject=args.external_subject,
        email=args.email.lower(),
        display_name=args.display_name,
        role=args.role,
        create_tenant=tenant is None,
        create_user=user is None,
        create_membership=membership is None,
    )


def safe_database_error_details(exc: Exception) -> dict[str, str | None]:
    """Extrai somente metadados seguros; nunca SQL, params ou mensagem."""
    original = getattr(exc, "orig", None)
    sqlstate = (
        getattr(original, "sqlstate", None)
        or getattr(original, "pgcode", None)
    )
    diag = getattr(original, "diag", None)
    constraint = getattr(diag, "constraint_name", None) if diag is not None else None
    return {
        "error_type": type(exc).__name__,
        "sqlstate": str(sqlstate) if sqlstate else None,
        "constraint": str(constraint) if constraint else None,
    }


def apply_plan(
    db: Session,
    plan: BootstrapPlan,
) -> None:
    if plan.create_tenant:
        db.add(Tenant(id=plan.tenant_id, name=plan.tenant_name))
    if plan.create_user:
        db.add(
            User(
                id=plan.user_id,
                external_subject=plan.external_subject,
                email=plan.email,
                display_name=plan.display_name,
            )
        )

    # Tenant e User são pais FK de Membership. Flush mantém tudo na mesma
    # transação, mas garante a ordem de INSERT antes do filho.
    if plan.create_tenant or plan.create_user:
        db.flush()

    if plan.create_membership:
        db.add(
            Membership(
                tenant_id=plan.tenant_id,
                user_id=plan.user_id,
                role=plan.role,
                active=True,
            )
        )
    db.commit()


def main() -> int:
    args = parser().parse_args()
    with SessionLocal() as db:
        try:
            plan = build_plan(db, args)
        except RuntimeError as exc:
            print(
                json.dumps(
                    {
                        "status": "CONFLICT",
                        "code": str(exc),
                        "write_executed": False,
                    }
                )
            )
            return 2

        output = {
            "status": "PREVIEW",
            "plan": asdict(plan),
            "write_executed": False,
        }
        if not args.apply:
            print(json.dumps(output, indent=2))
            return 0

        if args.confirm != "APPLY_BOOTSTRAP":
            print(
                json.dumps(
                    {
                        "status": "CONFIRMATION_REQUIRED",
                        "write_executed": False,
                    }
                )
            )
            return 3

        try:
            apply_plan(db, plan)
        except Exception:
            db.rollback()
            print(
                json.dumps(
                    {
                        "status": "FAILED",
                        "write_executed": False,
                    }
                )
            )
            return 4

        print(
            json.dumps(
                {
                    "status": "APPLIED",
                    "plan": asdict(plan),
                    "write_executed": True,
                },
                indent=2,
            )
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
