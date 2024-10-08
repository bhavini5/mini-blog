"""adding activity log

Revision ID: 74ddf44092dc
Revises: 834fde35eb89
Create Date: 2024-08-02 11:07:16.111352

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '74ddf44092dc'
down_revision = '834fde35eb89'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('activity_log', schema=None) as batch_op:
        batch_op.alter_column('timestamp',
               existing_type=postgresql.TIMESTAMP(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('activity_log', schema=None) as batch_op:
        batch_op.alter_column('timestamp',
               existing_type=postgresql.TIMESTAMP(),
               nullable=True)

    # ### end Alembic commands ###
