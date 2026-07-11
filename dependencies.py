import os
from datetime import datetime
from fastapi import Depends, HTTPException, Request, status
import jwt
import hashlib
from sqlalchemy.orm import Session
from models import DenylistToken, User
from database import get_db
from security_engine import sec

def validar_csrf(request: Request):
    """
    Defesa: REQ-65 - Verificação de Origin/Referer contra ataques CSRF
    Defesa: RNF-05 - As origens são carregadas dinamicamente das variáveis de ambiente.
    """
    origem = request.headers.get("origin")
    referer = request.headers.get("referer")
    
    # RNF-05: Puxa do .env. O valor por defeito serve apenas como fallback para desenvolvimento local se a variável falhar
    allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "https://front-oficial.com,http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173")
    origens_permitidas = [origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()]
    
    origem_cliente = origem or referer
    
    if not origem_cliente:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail={"code": "SEC_001", "message": "Tentativa de CSRF bloqueada: Origem desconhecida"}
        )
        
    if origem_cliente.endswith('/'):
        origem_cliente = origem_cliente[:-1]
        
    if origem_cliente not in origens_permitidas:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "SEC_002", "message": "Tentativa de CSRF bloqueada: Origem não autorizada"}
        )

    csrf_header = request.headers.get("x-csrf-token")
    csrf_cookie = request.cookies.get("csrf_token")

    if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "SEC_003", "message": "Token CSRF inválido ou ausente"}
        )

def get_current_active_user(request: Request, db: Session = Depends(get_db)):
    """
    Defesa: REQ-22, REQ-26 e REQ-27 - Verificador Global de Sessões
    Inclui validação de Denylist e Fingerprint de Rede/Dispositivo.
    """
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente ou formato inválido")
    
    token = auth_header.split(" ")[1]
    
    try:
        payload = jwt.decode(token, sec.jwt_pub_pem, algorithms=["RS256"])
        jti = payload.get("jti")
        user_id = payload.get("sub")
        iat = payload.get("iat") # Extrai a hora de emissão do token
        
        if db.query(DenylistToken).filter(DenylistToken.jti == jti).first():
            raise HTTPException(status_code=401, detail="Token revogado (Logout realizado)")

        # Puxamos o utilizador para validar eventos que ocorreram DEPOIS do token ser emitido
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="Utilizador inexistente.")

        # FIX REQ-25: Invalidação de Sessões Anteriores à Troca de Senha
        if user.last_password_change and iat:
            token_emitted_at = datetime.utcfromtimestamp(iat)
            # Se o token foi gerado antes da última mudança de senha, é lixo!
            if token_emitted_at < user.last_password_change:
                raise HTTPException(status_code=401, detail="Sessão expirada. A senha da conta foi alterada recentemente.")
            
        current_ip_hash = hashlib.sha256(request.client.host.encode('utf-8')).hexdigest()
        current_ua_hash = hashlib.sha256(request.headers.get("user-agent", "").encode('utf-8')).hexdigest()
        
        if payload.get("ip_hash") != current_ip_hash or payload.get("ua_hash") != current_ua_hash:
            raise HTTPException(status_code=401, detail="Token inválido: Alteração de rede/dispositivo detetada.")
            
        return user_id 
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido ou adulterado")