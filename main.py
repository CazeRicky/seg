import os
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from routers.auth import limiter # Importa o limitador do auth.py
from fastapi.exceptions import RequestValidationError

# 1. Carrega as variáveis do .env ANTES de qualquer outra coisa
load_dotenv()

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
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "https://front-oficial.com,http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173")
origens_permitidas = [origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origens_permitidas,
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
    response.headers["X-XSS-Protection"] = "0" 
    
    # REQ-43: Aplica o no-store APENAS nas rotas da API, protegendo a performance do Frontend (React)
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
        
    return response

# ---------- PADRONIZAÇÃO DE ERROS ----------

# ---------- PADRONIZAÇÃO DE ERROS ----------

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Defesa: RNF-14 - Padroniza os erros gerados pelas validações do Pydantic.
    Lista detalhadamente os campos que falharam a validação sem esconder a informação.
    """
    # Mapeia todos os erros e constrói a lista detalhada para o Frontend
    detalhes = [{"campo": ".".join(map(str, erro.get("loc", []))), "motivo": erro.get("msg")} for erro in exc.errors()]
    
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "code": "VAL_001",
            "message": "Falha na validação dos dados enviados.",
            "detalhes": detalhes,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

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

# Registra o Rate Limiter na aplicação
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)