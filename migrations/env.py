from logging.config import fileConfig
from alembic import context
from sqlalchemy import create_engine,pool
from orkio_v2.config import get_settings
from orkio_v2.database import Base, normalize_database_url
from orkio_v2 import models
config=context.config
target_metadata=Base.metadata
def resolve_url() -> str:
    return normalize_database_url(get_settings().database_url)
def run_migrations_offline():
    context.configure(url=resolve_url(),target_metadata=target_metadata,literal_binds=True)
    with context.begin_transaction(): context.run_migrations()
def run_migrations_online():
    connectable=create_engine(resolve_url(),poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection,target_metadata=target_metadata)
        with context.begin_transaction(): context.run_migrations()
run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
