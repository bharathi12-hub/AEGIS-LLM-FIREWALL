"""initial AEGIS schema: tenants, api_keys, audit (hash-chained), policies

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-09
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String()),
        sa.Column("fail_mode", sa.String()),
        sa.Column("policy_version", sa.Integer()),
        sa.Column("created_at", sa.Float()),
    )
    op.create_table(
        "api_keys",
        sa.Column("key_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), index=True),
        sa.Column("hashed_secret", sa.String()),
        sa.Column("role", sa.String()),
        sa.Column("active", sa.Boolean()),
        sa.Column("created_at", sa.Float()),
        sa.Column("rotated_from", sa.String(), nullable=True),
    )
    op.create_table(
        "audit",
        sa.Column("seq", sa.BigInteger(), primary_key=True, autoincrement=False),
        sa.Column("tenant_id", sa.String(), index=True),
        sa.Column("ts", sa.Float()),
        sa.Column("event", sa.String()),
        sa.Column("layer", sa.String()),
        sa.Column("verdict", sa.String()),
        sa.Column("reason", sa.String()),
        sa.Column("prev_hash", sa.String()),
        sa.Column("record_hash", sa.String()),
        sa.Column("payload_digest", sa.String()),
        sa.Column("meta", sa.Text()),
    )
    op.create_index("idx_audit_tenant", "audit", ["tenant_id"])
    op.create_table(
        "policies",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("yaml_text", sa.Text()),
        sa.Column("author", sa.String()),
        sa.Column("ts", sa.Float()),
    )


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_index("idx_audit_tenant", table_name="audit")
    op.drop_table("audit")
    op.drop_table("api_keys")
    op.drop_table("tenants")
