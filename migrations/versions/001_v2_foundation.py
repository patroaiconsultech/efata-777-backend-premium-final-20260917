"""ORKIO v2 foundation
Revision ID: 001_v2_foundation
Revises:
"""
from alembic import op
from orkio_v2.database import Base
from orkio_v2 import models
revision="001_v2_foundation"
down_revision=None
branch_labels=None
depends_on=None
def upgrade():
    bind=op.get_bind()
    Base.metadata.create_all(bind=bind)
def downgrade():
    bind=op.get_bind()
    Base.metadata.drop_all(bind=bind)
