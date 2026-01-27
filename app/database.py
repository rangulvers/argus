"""Database setup and session management"""

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
from typing import Dict, Any
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


@contextmanager
def get_middleware_db():
    """
    Context manager for middleware database sessions.
    
    This ensures proper session cleanup even if exceptions occur
    during middleware processing. Unlike get_db() which uses yield,
    this uses a try/finally context manager pattern.
    
    Usage:
        with get_middleware_db() as db:
            # Use db session
            user = db.query(User).first()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_engine():
    """Get the database engine instance"""
    return engine


def get_pool_status() -> Dict[str, Any]:
    """
    Get connection pool statistics for monitoring.
    
    Returns:
        Dict containing pool size, checked out connections,
        overflow connections, and other pool metrics.
        
    Note:
        For SQLite, pool statistics are limited as it uses
        a NullPool or StaticPool by default.
    """
    pool = engine.pool
    
    try:
        # Try to get pool statistics - handle both properties and methods
        pool_size = pool.size if isinstance(pool.size, int) else pool.size()
        checked_out = pool.checkedout() if callable(pool.checkedout) else getattr(pool, "checkedout", 0)
        
        return {
            "pool_size": pool_size,
            "checked_out": checked_out,
            "overflow": pool.overflow() if hasattr(pool, "overflow") and callable(pool.overflow) else 0,
            "checked_in": pool_size - checked_out,
            "pool_class": pool.__class__.__name__,
            "database_url": DATABASE_URL.split("://")[0] + "://***",  # Hide credentials
        }
    except (AttributeError, TypeError) as e:
        # Some pool types (NullPool, StaticPool) don't have all methods
        logger.debug(f"Pool statistics not fully available: {e}")
        return {
            "pool_class": pool.__class__.__name__,
            "database_url": DATABASE_URL.split("://")[0] + "://***",
            "note": "Full pool statistics not available for this pool type"
        }


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
