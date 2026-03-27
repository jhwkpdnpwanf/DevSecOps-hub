import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.orm import sessionmaker

from app.database.models import Base

load_dotenv()

DEFAULT_SQLITE_URL = "sqlite:///./devsecops_hub.db"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)

url_obj = make_url(DATABASE_URL)
DB_BACKEND = url_obj.get_backend_name()

engine_kwargs = {"pool_pre_ping": True}
if DB_BACKEND == "sqlite":
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_database_if_not_exists() -> None:
    if DB_BACKEND in {"sqlite"}:
        return

    db_name = url_obj.database
    if not db_name:
        return

    server_url = url_obj.set(database=None)
    temp_engine = create_engine(server_url.render_as_string(hide_password=False), pool_pre_ping=True)

    create_stmt = None
    if DB_BACKEND.startswith("mysql"):
        create_stmt = f"CREATE DATABASE IF NOT EXISTS `{db_name}`"
    elif DB_BACKEND.startswith("postgresql"):
        create_stmt = f'CREATE DATABASE "{db_name}"'

    if not create_stmt:
        temp_engine.dispose()
        return

    try:
        with temp_engine.connect() as conn:
            if DB_BACKEND.startswith("postgresql"):
                exists = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname=:db_name"),
                    {"db_name": db_name},
                ).scalar()
                if not exists:
                    conn.execute(text(create_stmt))
                    conn.commit()
            else:
                conn.execute(text(create_stmt))
                conn.commit()
    finally:
        temp_engine.dispose()


def init_db(force_drop: bool = False) -> None:
    create_database_if_not_exists()

    if force_drop:
        Base.metadata.drop_all(bind=engine)

    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()