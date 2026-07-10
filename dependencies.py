import os
from fastapi import Depends, HTTPException, Request, status
import jwt
import hashlib
from sqlalchemy.orm import Session
from models import DenylistToken
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
        # 1. Descodifica e valida a assinatura usando a chave pública (RS256)
        payload = jwt.decode(token, sec.jwt_pub_pem, algorithms=["RS256"])
        jti = payload.get("jti")
        user_id = payload.get("sub")
        
        # 2. Verifica se o JTI está na Denylist (Logout realizado)
        if db.query(DenylistToken).filter(DenylistToken.jti == jti).first():
            raise HTTPException(status_code=401, detail="Token revogado (Logout realizado)")
            
        # 3. Defesa REQ-26 e REQ-27: Fingerprint Check (Anti-Roubo de Token)
        current_ip = request.client.host
        current_ua = request.headers.get("user-agent", "")
        
        current_ip_hash = hashlib.sha256(current_ip.encode('utf-8')).hexdigest()
        current_ua_hash = hashlib.sha256(current_ua.encode('utf-8')).hexdigest()
        
        # Se o token foi roubado e está a ser usado noutra rede ou navegador, a requisição é bloqueada
        if payload.get("ip_hash") != current_ip_hash:
            raise HTTPException(status_code=401, detail="Token inválido: Alteração de rede (IP) detetada.")
            
        if payload.get("ua_hash") != current_ua_hash:
            raise HTTPException(status_code=401, detail="Token inválido: Alteração de dispositivo/navegador detetada.")
            
        return user_id 
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido ou adulterado")