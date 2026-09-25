from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Metadata commune aux futurs modèles et à Alembic."""
