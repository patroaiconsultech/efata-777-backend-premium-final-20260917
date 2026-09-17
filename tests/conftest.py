import os
# A suite deve ser deterministica e nao herdar credenciais do ambiente.
# Sem isto, uma OPENAI_API_KEY presente no host faria os testes de
# fail-closed exercitarem a chamada real ao provedor de LLM.
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("GEMINI_API_KEY", None)
os.environ.pop("GOOGLE_API_KEY", None)
os.environ.update({
 "PLATFORM_ENVIRONMENT":"test","PLATFORM_AUTH_MODE":"test",
  "PLATFORM_INVITATION_TOKEN_SECRET":"x"*40,"DATABASE_URL":"sqlite+pysqlite:///:memory:","PLATFORM_ALLOWED_ORIGINS":"http://localhost:5173,https://plataforma-efata-777-frontend-production.up.railway.app"

})
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from orkio_v2.main import app
from orkio_v2.database import Base,get_db
from orkio_v2.models import Tenant,User,Membership
engine=create_engine("sqlite+pysqlite:///:memory:",connect_args={"check_same_thread":False},poolclass=StaticPool)
Testing=sessionmaker(bind=engine,expire_on_commit=False)
Base.metadata.create_all(engine)
with engine.begin() as connection:
    connection.exec_driver_sql(
        "CREATE TABLE IF NOT EXISTS alembic_version "
        "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
    )
    connection.exec_driver_sql("DELETE FROM alembic_version")
    connection.exec_driver_sql(
        "INSERT INTO alembic_version(version_num) "
        "VALUES ('012_platform_user_invitations')"
    )

def override_db():
    db=Testing()
    try: yield db
    finally: db.close()
app.dependency_overrides[get_db]=override_db
@pytest.fixture()
def client():
    with Testing() as db:
      if not db.get(Tenant,"tenant-1"):
        db.add(Tenant(id="tenant-1",name="Test"))
        db.add(User(id="user-1",external_subject="sub-1",email="owner@example.com",display_name="Owner"))
        db.add(User(id="user-2",external_subject="sub-2",email="guest@example.com",display_name="Guest"))
        db.add(Membership(tenant_id="tenant-1",user_id="user-1",role="admin"))
        db.commit()
    return TestClient(app)
def headers(user="user-1",roles="admin",tenant="tenant-1",subject=None):
    email = "guest@example.com" if user == "user-2" else "owner@example.com"
    if subject is None:
        subject = user.replace("user-", "sub-", 1)
    return {
        "X-Test-User": user,
        "X-Test-Tenant": tenant,
        "X-Test-Roles": roles,
        "X-Test-Email": email,
        "X-Test-Subject": subject,
    }


@pytest.fixture()
def live_headers():
    return headers()


@pytest.fixture()
def live_client(client, monkeypatch):
    """Cliente com a chave real injetada, para o teste de integracao opcional.

    A chave e lida de ORKIO_LIVE_OPENAI_KEY para deixar explicito que se
    trata de uso deliberado, e nunca e registrada em log.
    """
    from orkio_v2.config import get_settings

    key = os.environ.get("ORKIO_LIVE_OPENAI_KEY", "")
    if not key:
        pytest.skip("ORKIO_LIVE_OPENAI_KEY nao definida.")
    monkeypatch.setattr(get_settings(), "openai_api_key", key, raising=False)
    return client
