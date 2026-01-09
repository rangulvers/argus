"""Database setup and session management"""

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import logging

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/argus.db")

# Create engine
# For SQLite, we need to enable check_same_thread=False to allow FastAPI to use it
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """Dependency for getting database sessions"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_migrations():
    """Run schema migrations to add missing columns"""
    inspector = inspect(engine)

    # Define migrations: (table_name, column_name, column_type)
    migrations = [
        ("devices", "zone", "VARCHAR(100)"),
        ("device_history", "zone", "VARCHAR(100)"),
    ]

    with engine.connect() as conn:
        for table_name, column_name, column_type in migrations:
            # Check if table exists
            if table_name not in inspector.get_table_names():
                continue

            # Check if column exists
            columns = [col["name"] for col in inspector.get_columns(table_name)]
            if column_name not in columns:
                try:
                    conn.execute(text(
                        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
                    ))
                    conn.commit()
                    logger.info(f"Added column {column_name} to {table_name}")
                except Exception as e:
                    logger.warning(f"Could not add column {column_name} to {table_name}: {e}")


def init_db():
    """Initialize database - create all tables and run migrations"""
    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Run migrations for any missing columns
    run_migrations()
