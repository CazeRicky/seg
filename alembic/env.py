from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context

import os
import sys
from dotenv import load_dotenv #puxa a biblioteca q le o arquivo .env

#forca o python a enxergar a raiz do projeto
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import models

#carrega as variaveis do .env pra memoria
load_dotenv()

#this is the Alembic Config object...
config = context.config

#tenta puxar a string do banco
db_url = os.getenv("DB_CONNECTION_STRING")

#defesa:trava pra gente saber se o windows sabotou o arquivo .env
if not db_url:
    raise ValueError("ERRO CRITICO: O Python não achou a variável DB_CONNECTION_STRING! Verifique se o arquivo não foi salvo como .env.txt por engano.")

#sobrepoe a configuracao padrao do alembic
config.set_main_option("sqlalchemy.url", db_url)

#Interpret the config file for Python logging...
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

#target_metadata = None
target_metadata = models.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


from sqlalchemy import create_engine # Adicione isso caso não tenha lá em cima

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    db_url = os.getenv("DB_CONNECTION_STRING")
    
    # Trava de segurança para garantir que leu o .env
    if not db_url:
        raise ValueError("ERRO CRÍTICO: Variável DB_CONNECTION_STRING não encontrada!")

    # DEFESA: Ignora o alembic.ini completamente e cria a conexão direto com a string do .env!
    connectable = create_engine(db_url, poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
