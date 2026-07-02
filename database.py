import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Carrega as variáveis do ficheiro .env
load_dotenv()

# Vai buscar a string de ligação que configurou no .env
SQLALCHEMY_DATABASE_URL = os.getenv("DB_CONNECTION_STRING")

if not SQLALCHEMY_DATABASE_URL:
    raise ValueError("ERRO CRÍTICO: Variável DB_CONNECTION_STRING não encontrada no .env!")

# Cria o motor de ligação ao PostgreSQL
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Cria a classe que vai gerar as sessões de base de dados para cada requisição
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Garante a criação das tabelas conforme os modelos declarados
from models import Base
Base.metadata.create_all(bind=engine)

# Função de dependência para o FastAPI usar nas rotas
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()