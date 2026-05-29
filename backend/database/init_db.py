# =============================================================
#   NetScope AI — Database Bootstrapper
#   Creates the SQLite database and all required tables
# =============================================================

from backend.database.database import engine, Base
from backend.database import models

def init_db():
    """Initializes the database and automatically creates all tables if they don't exist."""
    print("   💾  Initializing NetScope SQLite Database tables...")
    Base.metadata.create_all(bind=engine)
    print("   ✅  Database tables initialized successfully.")

if __name__ == "__main__":
    init_db()
