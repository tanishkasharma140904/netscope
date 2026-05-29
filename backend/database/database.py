# =============================================================
#   NetScope AI — Database Configuration
#   Configures SQLAlchemy SQLite connections and sessions
# =============================================================

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Set database path in this directory
DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "netscope.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create engine with connect_args for thread safety in multi-threaded app (Scapy + FastAPI)
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

def get_db():
    """FastAPI dependency to retrieve database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
