"""Initial migration

Revision ID: 001_initial
Revises: 
Create Date: 2025-01-07

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create request_logs table
    op.create_table(
        'request_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('request_id', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('original_prompt', sa.Text(), nullable=False),
        sa.Column('modified_prompt', sa.Text(), nullable=True),
        sa.Column('original_response', sa.Text(), nullable=True),
        sa.Column('modified_response', sa.Text(), nullable=True),
        sa.Column('decision', sa.Enum('block', 'redact', 'warn', 'allow', name='decision'), nullable=False),
        sa.Column('risks', sa.JSON(), nullable=False),
        sa.Column('request_metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_request_logs_id'), 'request_logs', ['id'], unique=False)
    op.create_index(op.f('ix_request_logs_request_id'), 'request_logs', ['request_id'], unique=True)

    # Create policy_rules table
    op.create_table(
        'policy_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('risk_type', sa.Enum('PII', 'PHI', 'PROMPT_INJECTION', 'OTHER', name='risktype'), nullable=False),
        sa.Column('pattern', sa.String(), nullable=False),
        sa.Column('pattern_type', sa.String(), nullable=False),
        sa.Column('severity', sa.Enum('high', 'medium', 'low', name='severity'), nullable=False),
        sa.Column('action', sa.Enum('block', 'redact', 'warn', 'allow', name='decision'), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_policy_rules_id'), 'policy_rules', ['id'], unique=False)

    # Create admin_users table
    op.create_table(
        'admin_users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_superuser', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )
    op.create_index(op.f('ix_admin_users_id'), 'admin_users', ['id'], unique=False)
    op.create_index(op.f('ix_admin_users_email'), 'admin_users', ['email'], unique=True)
    op.create_index(op.f('ix_admin_users_username'), 'admin_users', ['username'], unique=True)

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('admin_user_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('resource_type', sa.String(), nullable=False),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_logs_id'), table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_index(op.f('ix_admin_users_username'), table_name='admin_users')
    op.drop_index(op.f('ix_admin_users_email'), table_name='admin_users')
    op.drop_index(op.f('ix_admin_users_id'), table_name='admin_users')
    op.drop_table('admin_users')
    op.drop_index(op.f('ix_policy_rules_id'), table_name='policy_rules')
    op.drop_table('policy_rules')
    op.drop_index(op.f('ix_request_logs_request_id'), table_name='request_logs')
    op.drop_index(op.f('ix_request_logs_id'), table_name='request_logs')
    op.drop_table('request_logs')
    
    # Drop enums
    sa.Enum(name='decision').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='risktype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='severity').drop(op.get_bind(), checkfirst=True)

