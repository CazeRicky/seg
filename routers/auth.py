import os
import smtplib
import io
import base64
import pyotp
import secrets
import uuid
import re
import jwt
import json
from email.message import EmailMessage
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
# Importa as tabelas da base de dados que estão no ficheiro models.py
from dependencies import validar_csrf, get_current_active_user

# Importa a função que fornece a sessão da base de dados
from database import get_db

# Importações dos seus modelos e banco de dados
from models import User, RefreshSession, DenylistToken, AuditLog, WebAuthnPasskey
from security_engine import sec

# Importações do WebAuthn (FIDO2)
from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response
)
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential

# Configurações do Relying Party
RP_ID = "localhost" 
RP_NAME = "Sistema de Assinaturas UABJ"
ORIGIN = "http://localhost:3000" 

# Cache em memória para os desafios do WebAuthn (Idealmente usar Redis em produção)
challenge_cache = {}

router = APIRouter(prefix="/api/v1/auth")
limiter = Limiter(key_func=get_remote_address)


def enviar_email_notificacao(destinatario: str, assunto: str, corpo: str) -> bool:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = os.getenv("SMTP_PORT", "").strip()
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "").strip()

    if not all([smtp_host, smtp_port, smtp_user, smtp_password, smtp_from]):
        print("[EMAIL DESATIVADO] variáveis SMTP incompletas; e-mail não enviado.")
        return False

    mensagem = EmailMessage()
    mensagem["Subject"] = assunto
    mensagem["From"] = smtp_from
    mensagem["To"] = destinatario
    mensagem.set_content(corpo)

    try:
        with smtplib.SMTP(smtp_host, int(smtp_port), timeout=10) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(mensagem)
        return True
    except Exception as exc:
        print(f"[EMAIL ERRO] falha ao enviar e-mail: {exc}")
        return False


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str = None 

    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        # Defesa: REQ-01. Mínimo 12 chars, 1 maiúscula, 1 minúscula, 1 número, 1 símbolo
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$"
        if not re.match(pattern, v):
            raise ValueError("A senha não atende aos requisitos mínimos de complexidade.")
        return v

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None

    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$"
        if not re.match(pattern, v):
            raise ValueError("A senha não atende aos requisitos mínimos de complexidade.")
        return v

class TotpEnableRequest(BaseModel):
    totp_code: str

# ==========================================
# 1. LOGIN BLINDADO (REQ-03, REQ-04, REQ-05, REQ-15)
# ==========================================
@router.post("/login")
@limiter.limit("10/minute")
def login_endpoint(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    
    if not user:
        raise HTTPException(status_code=401, detail={"code": "AUTH_001", "message": "Credenciais inválidas"})

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(status_code=403, detail={"code": "AUTH_004", "message": "Conta bloqueada."})

    if not sec.verify_password(req.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        
        db.add(AuditLog(user_id=user.id, action="LOGIN_FAILED", ip_address=request.client.host))
        db.commit()
        raise HTTPException(status_code=401, detail={"code": "AUTH_001", "message": "Credenciais inválidas"})

    user.failed_login_attempts = 0
    db.commit()

    if user.is_totp_enabled:
        if not req.totp_code or not sec.verify_totp(user.totp_secret, req.totp_code):
            db.add(AuditLog(user_id=user.id, action="LOGIN_FAILED_2FA", ip_address=request.client.host))
            db.commit()
            raise HTTPException(status_code=401, detail={"code": "AUTH_003", "message": "Código 2FA inválido"})

    session_id = str(uuid.uuid4())
    access_jwt, jti = sec.generate_access_token(user.id, request.client.host, request.headers.get("user-agent", ""), session_id)
    refresh_token = sec.generate_refresh_token()
    
    db.add(RefreshSession(
        id=refresh_token, user_id=user.id, 
        expires_at=datetime.utcnow() + timedelta(days=7),
        ip_address=request.client.host, user_agent=request.headers.get("user-agent", "")
    ))
    db.commit()

    use_secure_cookie = os.getenv("ENVIRONMENT", "development").lower() == "production"
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=use_secure_cookie,
        samesite="Lax",
        max_age=604800,
    )
    return {"access_token": access_jwt, "csrf_token": str(uuid.uuid4())}

# ==========================================
# 2. REGISTRO DE USUÁRIO
# ==========================================
@router.post("/register")
def register_endpoint(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == req.username) | (User.email == req.email)).first()
    if existing:
        raise HTTPException(status_code=409, detail="Nome de usuário ou e-mail já registrado")

    user_id = str(uuid.uuid4())
    password_hash = sec.hash_password(req.password)
    rsa_priv_encrypted, rsa_pub = sec.generate_user_rsa_keys(req.username)

    user = User(
        id=user_id,
        username=req.username,
        email=req.email.lower() if req.email else None,
        password_hash=password_hash,
        rsa_pub=rsa_pub,
        rsa_priv_encrypted=rsa_priv_encrypted,
        is_totp_enabled=False,
        totp_secret=None,
        backup_codes=None
    )

    db.add(user)
    db.add(AuditLog(user_id=user_id, action="USER_REGISTERED", ip_address=request.client.host, user_agent=request.headers.get("user-agent", ""), details=json.dumps({"username": req.username})))
    db.commit()

    return {"message": "Usuário registrado com sucesso", "user_id": user_id}

# ==========================================
# 3. CONFIGURAÇÃO DO TOTP (REQ-12, REQ-13, REQ-14)
# ==========================================
@router.post("/totp/setup")
def setup_totp(request: Request, db: Session = Depends(get_db), current_user_id: str = Depends(get_current_active_user)):
    user = db.query(User).filter(User.id == current_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    totp_secret = sec.generate_totp_secret()
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="Sistema de Assinaturas")

    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    backup_codes_hashes = [sec.hash_password(code) for code in backup_codes]

    user.totp_secret = totp_secret
    user.backup_codes = json.dumps(backup_codes_hashes)
    db.commit()

    qr_code_data_url = None
    try:
        import qrcode
        qr = qrcode.QRCode(border=1)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        qr_code_data_url = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("utf-8")
    except ImportError:
        qr_code_data_url = None

    return {
        "secret": totp_secret,
        "qr_code_uri": provisioning_uri,
        "qr_code_image": qr_code_data_url,
        "backup_codes": backup_codes
    }

@router.post("/totp/enable")
def enable_totp(req: TotpEnableRequest, request: Request, db: Session = Depends(get_db), current_user_id: str = Depends(get_current_active_user)):
    user = db.query(User).filter(User.id == current_user_id).first()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="Configuração TOTP não encontrada")

    if not sec.verify_totp(user.totp_secret, req.totp_code):
        raise HTTPException(status_code=401, detail="Código TOTP inválido")

    user.is_totp_enabled = True
    db.commit()
    db.add(AuditLog(user_id=current_user_id, action="TOTP_ENABLED", ip_address=request.client.host, user_agent=request.headers.get("user-agent", ""), details=json.dumps({"method": "totp"})))
    db.commit()

    return {"message": "Autenticação de dois fatores habilitada com sucesso"}

# ==========================================
# 3. WEBAUTHN - REGISTRO DE DISPOSITIVO (REQ-06, REQ-07)
# ==========================================
@router.post("/webauthn/register/generate")
def webauthn_register_generate(request: Request, db: Session = Depends(get_db)):
    user_id = "uuid-do-banco" # Substituir pela extração real via JWT
    user = db.query(User).filter(User.id == user_id).first()

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user.id.encode('utf-8'),
        user_name=user.username,
    )
    
    challenge_cache[user.id] = options.challenge
    return json.loads(options.json())

@router.post("/webauthn/register/verify")
def webauthn_register_verify(req_data: dict, request: Request, db: Session = Depends(get_db)):
    user_id = "uuid-do-banco" # Substituir pela extração real via JWT
    expected_challenge = challenge_cache.get(user_id)
    
    if not expected_challenge:
        raise HTTPException(status_code=400, detail="Challenge expirado")

    try:
        credential = RegistrationCredential.parse_raw(json.dumps(req_data))
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )
        
        db.add(WebAuthnPasskey(
            id=str(uuid.uuid4()),
            user_id=user_id, 
            credential_id=verification.credential_id.hex(), 
            public_key=verification.credential_public_key.hex(), 
            sign_count=verification.sign_count
        ))
        db.commit()
        
        del challenge_cache[user_id] 
        return {"message": "Biometria registrada com sucesso!"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Falha no registro: {str(e)}")

# ==========================================
# 4. WEBAUTHN - LOGIN COM DISPOSITIVO (REQ-08)
# ==========================================
class WebauthnAuthRequest(BaseModel):
    username: str

@router.post("/webauthn/authenticate/generate")
def webauthn_auth_generate(req: WebauthnAuthRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    options = generate_authentication_options(rp_id=RP_ID)
    challenge_cache[user.id] = options.challenge
    return json.loads(options.json())

@router.post("/webauthn/authenticate/verify")
def webauthn_auth_verify(req_data: dict, request: Request, response: Response, db: Session = Depends(get_db)):
    credential_id_hex = req_data.get("id")
    device = db.query(WebAuthnPasskey).filter(WebAuthnPasskey.credential_id == credential_id_hex).first()
    
    if not device:
        raise HTTPException(status_code=401, detail="Dispositivo não reconhecido")

    expected_challenge = challenge_cache.get(device.user_id)
    
    try:
        credential = AuthenticationCredential.parse_raw(json.dumps(req_data))
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=bytes.fromhex(device.public_key),
            credential_current_sign_count=device.sign_count
        )
        
        if verification.new_sign_count <= device.sign_count and device.sign_count != 0:
            raise HTTPException(status_code=403, detail="Possível clonagem detectada!")
            
        device.sign_count = verification.new_sign_count
        db.commit()

        session_id = str(uuid.uuid4())
        access_jwt, jti = sec.generate_access_token(device.user_id, request.client.host, request.headers.get("user-agent", ""), session_id)
        refresh_token = sec.generate_refresh_token()
        
        db.add(RefreshSession(
            id=refresh_token, user_id=device.user_id, 
            expires_at=datetime.utcnow() + timedelta(days=7),
            ip_address=request.client.host, user_agent=request.headers.get("user-agent", "")
        ))
        db.commit()

        response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=True, samesite="strict", max_age=604800)
        return {"access_token": access_jwt, "csrf_token": str(uuid.uuid4())}
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Falha na autenticação: {str(e)}")

# ==========================================
# 5. ROTA DE REFRESH COM ROTAÇÃO (REQ-29/30)
# ==========================================
@router.post("/refresh")
def refresh_token_endpoint(request: Request, response: Response, db: Session = Depends(get_db)):
    old_refresh = request.cookies.get("refresh_token")
    if not old_refresh: raise HTTPException(status_code=401, detail="Refresh token ausente")
    
    session_db = db.query(RefreshSession).filter(RefreshSession.id == old_refresh).first()
    
    if not session_db or session_db.is_revoked:
        if session_db:
            db.query(RefreshSession).filter(RefreshSession.user_id == session_db.user_id).update({"is_revoked": True})
            db.commit()
        raise HTTPException(status_code=403, detail="Sessão comprometida.")

    session_db.is_revoked = True
    new_refresh = sec.generate_refresh_token()
    
    db.add(RefreshSession(id=new_refresh, user_id=session_db.user_id, expires_at=datetime.utcnow() + timedelta(days=7)))
    db.commit()
    
    new_access, _ = sec.generate_access_token(session_db.user_id, request.client.host, "", "new_session_id")
    response.set_cookie(key="refresh_token", value=new_refresh, httponly=True, secure=True, samesite="strict", max_age=604800)
    return {"access_token": new_access}

# ==========================================
# 6. LOGOUT E DENYLIST (REQ-21/23)
# ==========================================

@router.post("/logout", dependencies=[Depends(validar_csrf)])
def logout_endpoint(request: Request, response: Response, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if auth_header:
        token = auth_header.split(" ")[1]
        payload = jwt.decode(token, sec.jwt_pub_pem, algorithms=["RS256"])
        
        db.add(DenylistToken(jti=payload["jti"], expires_at=datetime.utcfromtimestamp(payload["exp"])))
        
    old_refresh = request.cookies.get("refresh_token")
    if old_refresh:
        db.query(RefreshSession).filter(RefreshSession.id == old_refresh).update({"is_revoked": True})
        
    db.commit()
    response.delete_cookie("refresh_token")
    return {"message": "Logout seguro concluído"}