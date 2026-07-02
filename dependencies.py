from fastapi import Depends, HTTPException, Request, status
import jwt
from sqlalchemy.orm import Session
from models import DenylistToken
from database import get_db
from security_engine import sec

def validar_csrf(request: Request):
    """
    Defesa: REQ-65 - Verificação de Origin/Referer contra ataques CSRF
    """
    origem = request.headers.get("origin")
    referer = request.headers.get("referer")
    
    # Adicione aqui os domínios permitidos (devem coincidir com o CORS do main.py)
    origens_permitidas = ["https://front-oficial.com", "http://localhost:3000"]
    
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

def get_current_active_user(request: Request, db: Session = Depends(get_db)):
    """
    Defesa: REQ-22 - Verificador Global de Sessões (Denylist + Validação JWT)
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
            
        return user_id # Retorna o ID do utilizador autenticado
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido ou adulterado")