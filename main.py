import os
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.datastructures import MutableHeaders
from dotenv import load_dotenv
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from routers.auth import limiter
from fastapi.exceptions import RequestValidationError
import traceback
from starlette.exceptions import HTTPException as StarletteHTTPException


# 1. Carrega as variáveis do .env ANTES de qualquer outra coisa
load_dotenv()

# FIX REQ-08: Trava de segurança total. Impede o arranque se faltar ALGO crítico.
critical_vars = [
    "DB_CONNECTION_STRING", 
    "MASTER_KEY",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "SMTP_FROM"
]
missing_vars = [var for var in critical_vars if not os.getenv(var)]
if missing_vars:
    raise RuntimeError(f"ERRO CRÍTICO: Variáveis de ambiente obrigatórias ausentes no .env: {', '.join(missing_vars)}")

# 2. Trava de segurança: impede o sistema de ligar se não achar a senha do banco
if not os.getenv("DB_CONNECTION_STRING"):
    raise RuntimeError("ERRO CRÍTICO: DB_CONNECTION_STRING ausente no .env")

# 3. Importa as rotas DEPOIS que o ambiente já está carregado
from routers import auth, pdf

# 4. Inicia a aplicação
app = FastAPI(title="Sistema de Assinaturas", version="1.0", docs_url="/api/v1/docs")

# 5. Conecta as rotas à aplicação
app.include_router(auth.router)
app.include_router(pdf.router)

# 6. Serve o frontend React buildado em produção
frontend_dir = Path(__file__).resolve().parent / "frontend" / "dist"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    @app.get("/", include_in_schema=False)
    async def root_index():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return HTMLResponse(index_file.read_text(encoding="utf-8"), media_type="text/html")
        return HTMLResponse(
            "<html><body><h1>Frontend construído mas index.html não encontrado.</h1></body></html>",
            status_code=500,
        )

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_index(full_path: str):
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return HTMLResponse(index_file.read_text(encoding="utf-8"), media_type="text/html")
        return HTMLResponse(
            "<html><body><h1>Frontend construído mas index.html não encontrado.</h1></body></html>",
            status_code=500,
        )
else:
    @app.get("/", include_in_schema=False)
    async def root_not_built():
        return HTMLResponse(
            "<html><body><h1>Frontend não encontrado.</h1><p>Execute <code>npm run build</code> dentro de frontend.</p></body></html>"
        )

# ---------- PROTEÇÃO CORS ----------
# RNF-05: Origens dinâmicas retiradas do .env (sem hardcoding)
allowed_origins_str = os.getenv(
    "ALLOWED_ORIGINS",
    "https://front-oficial.com,http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001,http://localhost:5173,http://127.0.0.1:5173",
)
origens_permitidas = [origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()]

# Mesmo durante o desenvolvimento, permitimos localhost nas portas comuns para evitar bloqueios CORS.
for fallback_origin in [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]:
    if fallback_origin not in origens_permitidas:
        origens_permitidas.append(fallback_origin)

# Durante o desenvolvimento local, também aceitamos requisições com Origin null (por exemplo, páginas abertas via file://)
if os.getenv("ENVIRONMENT", "development").lower() != "production":
    if "null" not in origens_permitidas:
        origens_permitidas.append("null")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origens_permitidas,
    allow_origin_regex=r"http://(127\.0\.0\.1|localhost)(:[0-9]+)?",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
    max_age=86400 
)

# CORSMiddleware já injeta Access-Control-Allow-Origin em todas as respostas para origens permitidas.
# Não injetar manualmente nos handlers para evitar cabeçalhos duplicados (Firefox rejeita).

# ---------- HTTP SECURITY HEADERS (ASGI puro — sem BaseHTTPMiddleware) ----------
class SecurityHeadersMiddleware:
    """Middleware ASGI puro que injeta cabeçalhos de segurança em todas as respostas.
    Usa a interface ASGI diretamente para evitar os problemas de BaseHTTPMiddleware
    com request bodies em Starlette 0.40+."""
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
                headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
                headers["X-Frame-Options"] = "DENY"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
                headers["X-XSS-Protection"] = "0"
                path = scope.get("path", "")
                if path.startswith("/api"):
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_security_headers)

app.add_middleware(SecurityHeadersMiddleware)

# ---------- PADRONIZAÇÃO DE ERROS ----------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Defesa: RNF-14 - Padroniza os erros gerados pelas validações do Pydantic.
    Lista detalhadamente os campos que falharam a validação sem esconder a informação.
    """
    detalhes = [{"campo": ".".join(map(str, erro.get("loc", []))), "motivo": erro.get("msg")} for erro in exc.errors()]
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "code": "VAL_001",
            "message": "Falha na validação dos dados enviados.",
            "detalhes": detalhes,
            "timestamp": datetime.utcnow().isoformat()
        },
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    content = {"timestamp": datetime.utcnow().isoformat()}
    
    if isinstance(exc.detail, dict):
        content.update(exc.detail)
    else:
        content["code"] = "SYS_000"
        content["message"] = str(exc.detail)
        
    return JSONResponse(status_code=exc.status_code, content=content)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import sys, traceback as _tb
    error_detail = f"{type(exc).__name__}: {exc}"
    tb_str = "".join(_tb.format_exception(type(exc), exc, exc.__traceback__))
    sys.stderr.write(f"\n[BACKEND 500] {error_detail}\n{tb_str}\n")
    sys.stderr.flush()
    sys.stdout.write(f"\n[BACKEND 500] {error_detail}\n{tb_str}\n")
    sys.stdout.flush()

    is_dev = os.getenv("ENVIRONMENT", "development").lower() != "production"
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": "SYS_001",
            "message": "Ocorreu um erro interno no servidor.",
            "detail": error_detail if is_dev else None,
            "traceback": tb_str if is_dev else None,
            "timestamp": datetime.utcnow().isoformat()
        },
    )

# Registra o Rate Limiter na aplicação
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)