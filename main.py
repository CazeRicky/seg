import os
from datetime import datetime
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from routers.auth import limiter # Importa o limitador do auth.py

# 1. Carrega as variáveis do .env ANTES de qualquer outra coisa
load_dotenv()

# 2. Trava de segurança: impede o sistema de ligar se não achar a senha do banco
if not os.getenv("DB_CONNECTION_STRING"):
    raise RuntimeError("ERRO CRÍTICO: DB_CONNECTION_STRING ausente no .env")

# 3. Importa as rotas DEPOIS que o ambiente já está carregado
from routers import auth

# 4. Inicia a aplicação
app = FastAPI(title="Sistema de Assinaturas", version="1.0", docs_url="/api/v1/docs")

# 5. Conecta o arquivo auth.py que está dentro da pasta routers
app.include_router(auth.router)

# ---------- PROTEÇÃO CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://front-oficial.com"], 
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
    max_age=86400 
)

# ---------- HTTP SECURITY HEADERS ----------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-XSS-Protection"] = "0" 
    return response

# ---------- PADRONIZAÇÃO DE ERROS ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": "SYS_001",
            "message": "Ocorreu um erro interno no servidor.",
            "timestamp": datetime.utcnow().isoformat()
        }
    )
app = FastAPI(title="Sistema de Assinaturas", version="1.0", docs_url="/api/v1/docs")
# Registra o Rate Limiter na aplicação
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)