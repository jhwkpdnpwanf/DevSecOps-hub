import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.database.models import Base
import pymysql

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
DB_SERVER_URL = DATABASE_URL.rsplit('/', 1)[0]
DB_NAME = DATABASE_URL.rsplit('/', 1)[1]

engine = create_engine(DATABASE_URL, pool_recycle=3600)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# DB 서버에 접속한 뒤 DB가 없으면 생성하는 함수
def create_database_if_not_exists():
    temp_engine = create_engine(DB_SERVER_URL)
    with temp_engine.connect() as conn:
        conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}"))
        conn.commit()
    temp_engine.dispose()
    print(f"[+] 데이터베이스 '{DB_NAME}' 확인 완료.")


# DB 초기화, 테이블 생성 함수
# force_drop = True 인 경우 기존 테이블을 삭제하고 새로 생성합니다. 
def init_db(force_drop=False):
    try:
        create_database_if_not_exists()
        
        if force_drop:
            print("[!] 모델 변경 감지: 기존 테이블을 삭제하고 새로 생성합니다.")
            Base.metadata.drop_all(bind=engine)
        
        Base.metadata.create_all(bind=engine)
        print("[+] 모든 테이블 생성 완료.")
    except Exception as e:
        print(f"[!] 초기화 중 오류 발생: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()