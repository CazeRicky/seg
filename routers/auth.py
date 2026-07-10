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
import hashlib
from email.message import EmailMessage
from datetime import datetime, timedelta
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from dependencies import validar_csrf, get_current_active_user
from database import get_db
from models import User, RefreshSession, DenylistToken, AuditLog, WebAuthnPasskey
from security_engine import sec
from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response
)
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential
from pydantic import BaseModel, field_validator

# Configurações do Relying Party
RP_ID = os.getenv("RP_ID")
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

    # FIX REQ-64: Escudo Anti-XSS que deteta scripts antes de o backend processar
    @field_validator('username', 'password', 'totp_code', mode='before')
    @classmethod
    def prevent_xss(cls, v):
        if isinstance(v, str) and re.search(r"[<>]", v):
            raise ValueError("Caracteres proibidos detetados (possível ataque XSS).")
        return v

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

    @field_validator('old_password', 'new_password', mode='before')
    @classmethod
    def prevent_xss(cls, v):
        if isinstance(v, str) and re.search(r"[<>]", v):
            raise ValueError("Caracteres proibidos detetados (possível ataque XSS).")
        return v

    @field_validator('new_password')
    @classmethod
    def validate_password_complexity(cls, v):
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$"
        if not re.match(pattern, v):
            raise ValueError("A nova senha não atende aos requisitos mínimos.")
        return v

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_password_complexity(cls, v):
        # Defesa: REQ-01. Mínimo 12 chars, 1 maiúscula, 1 minúscula, 1 número, 1 símbolo
        pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$"
        if not re.match(pattern, v):
            raise ValueError("A nova senha não atende aos requisitos mínimos de complexidade.")
        return v

class TotpEnableRequest(BaseModel):
    totp_code: str

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

# ==========================================
# 1. LOGIN BLINDADO
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
            # FIX REQ-03: Notificação por e-mail no bloqueio
            if user.email:
                enviar_email_notificacao(
                    user.email,
                    "Segurança: Conta Bloqueada",
                    f"A sua conta foi bloqueada por 15 minutos devido a múltiplas tentativas de login falhas a partir do IP {request.client.host}."
                )
        
        db.add(AuditLog(user_id=user.id, action="LOGIN_FAILED", ip_address=request.client.host))
        db.commit()
        raise HTTPException(status_code=401, detail={"code": "AUTH_001", "message": "Credenciais inválidas"})

    user.failed_login_attempts = 0
    db.commit()

    # FIX REQ-58: E-mail APENAS para novos logins de IPs desconhecidos
    ip_conhecido = db.query(RefreshSession).filter(
        RefreshSession.user_id == user.id,
        RefreshSession.ip_address == request.client.host
    ).first()

    if not ip_conhecido and user.email:
        enviar_email_notificacao(
            user.email,
            "Novo login de IP desconhecido",
            f"Um novo acesso foi realizado na sua conta a partir de um IP não reconhecido: {request.client.host}."
        )

    if user.is_totp_enabled:
        if not req.totp_code:
            raise HTTPException(status_code=401, detail={"code": "AUTH_003", "message": "Código 2FA ausente"})
            
        decrypted_secret = sec.decrypt_data(user.totp_secret)
        
        # 1. Tenta validar via Autenticador (TOTP Normal)
        is_totp_valid = sec.verify_totp(decrypted_secret, req.totp_code)
        is_backup_valid = False
        
        # 2. Se o TOTP falhar, tenta validar via Código de Backup (REQ-14)
        if not is_totp_valid and user.backup_codes:
            backup_codes_hashes = json.loads(user.backup_codes)
            for i, code_hash in enumerate(backup_codes_hashes):
                if sec.verify_password(req.totp_code, code_hash):
                    is_backup_valid = True
                    # Remove o código usado da lista (é de uso único)
                    backup_codes_hashes.pop(i)
                    user.backup_codes = json.dumps(backup_codes_hashes)
                    
                    db.add(AuditLog(user_id=user.id, action="BACKUP_CODE_USED", ip_address=request.client.host))
                    db.commit()
                    break # Código encontrado, para de procurar

        # 3. Se ambos falharem, bloqueia e avisa
        if not is_totp_valid and not is_backup_valid:
            # FIX REQ-16: Sistema de strikes para o TOTP
            user.failed_totp_attempts += 1
            
            if user.failed_totp_attempts >= 3:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.add(AuditLog(user_id=user.id, action="LOGIN_FAILED_2FA_LOCKED", ip_address=request.client.host))
                db.commit()
                if user.email:
                    enviar_email_notificacao(
                        user.email,
                        "Alerta Crítico: Múltiplas falhas no 2FA",
                        f"A sua conta foi bloqueada por 15 minutos após múltiplas tentativas de contornar o código 2FA a partir do IP {request.client.host}."
                    )
                raise HTTPException(status_code=403, detail={"code": "AUTH_004", "message": "Conta bloqueada por múltiplas falhas no 2FA."})
            
            db.commit()
            raise HTTPException(status_code=401, detail={"code": "AUTH_003", "message": "Código 2FA ou de recuperação inválido"})

        # Se acertou no 2FA, zera o contador de erros:
        user.failed_totp_attempts = 0

    session_id = str(uuid.uuid4())
    access_jwt, jti = sec.generate_access_token(user.id, request.client.host, request.headers.get("user-agent", ""), session_id)
    
    refresh_token = sec.generate_refresh_token()
    # FIX REQ-19: Armazenar o Refresh Token apenas como HASH
    refresh_token_hash = hashlib.sha256(refresh_token.encode('utf-8')).hexdigest()
    
    db.add(RefreshSession(
        id=refresh_token_hash, # Guarda APENAS o Hash na BD
        user_id=user.id, 
        expires_at=datetime.utcnow() + timedelta(days=7),
        ip_address=request.client.host, user_agent=request.headers.get("user-agent", "")
    ))
    db.commit()

    use_secure_cookie = os.getenv("ENVIRONMENT", "development").lower() == "production"
    csrf_token = generate_csrf_token()

    # FIX REQ-20: Cookie HttpOnly forçado para samesite="strict"
    response.set_cookie(
        key="refresh_token", value=refresh_token, httponly=True, secure=use_secure_cookie,
        samesite="strict", max_age=604800,
    )
    response.set_cookie(
        key="csrf_token", value=csrf_token, httponly=False, secure=use_secure_cookie,
        samesite="strict", max_age=604800,
    )

    return {
        "access_token": access_jwt,
        "csrf_token": csrf_token,
        "user": {
            "id": user.id, "username": user.username, "email": user.email, "is_totp_enabled": user.is_totp_enabled
        }
    }
# ==========================================
# 2. REGISTRO DE USUÁRIO
# ==========================================
@router.post("/register")
def register_endpoint(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == req.username) | (User.email == req.email.lower())).first()
    if existing:
        raise HTTPException(status_code=409, detail="Nome de usuário ou e-mail já registrado")

    user_id = str(uuid.uuid4())
    password_hash = sec.hash_password(req.password)
    rsa_priv_encrypted, rsa_pub = sec.generate_user_rsa_keys(req.username)

    user = User(
        id=user_id,
        username=req.username,
        email=req.email.lower(),
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

    if user.email:
        enviar_email_notificacao(
            user.email,
            "Bem-vindo ao SecureSign",
            f"Sua conta foi criada com sucesso com o usuário {user.username}."
        )

    return {
        "message": "Usuário registrado com sucesso",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_totp_enabled": user.is_totp_enabled,
        }
    }

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
    user.totp_secret = sec.encrypt_data(totp_secret)
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
    decrypted_secret = sec.decrypt_data(user.totp_secret)
    if not sec.verify_totp(decrypted_secret, req.totp_code):
        raise HTTPException(status_code=401, detail="Código TOTP inválido")
    
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="Configuração TOTP não encontrada")

    if not sec.verify_totp(user.totp_secret, req.totp_code):
        raise HTTPException(status_code=401, detail="Código TOTP inválido")

    user.is_totp_enabled = True
    db.commit()
    db.add(AuditLog(user_id=current_user_id, action="TOTP_ENABLED", ip_address=request.client.host, user_agent=request.headers.get("user-agent", ""), details=json.dumps({"method": "totp"})))
    db.commit()

    if user.email:
        enviar_email_notificacao(
            user.email,
            "2FA habilitado",
            "A autenticação de dois fatores foi habilitada em sua conta. Se você não reconhece essa ação, entre em contato com o administrador."
        )

    return {"message": "Autenticação de dois fatores habilitada com sucesso"}

# ==========================================
# 3. WEBAUTHN - REGISTRO DE DISPOSITIVO (REQ-06, REQ-07)
# ==========================================
@router.post("/webauthn/register/generate")
def webauthn_register_generate(current_user_id: str = Depends(get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user.id.encode('utf-8'),
        user_name=user.username,
    )
    
    challenge_cache[user.id] = options.challenge
    return json.loads(options.json())

@router.post("/webauthn/register/verify")
def webauthn_register_verify(req_data: dict, current_user_id: str = Depends(get_current_active_user), db: Session = Depends(get_db)):
    expected_challenge = challenge_cache.get(current_user_id)
    
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
            user_id=current_user_id, 
            credential_id=verification.credential_id.hex(), 
            public_key=verification.credential_public_key.hex(), 
            sign_count=verification.sign_count,
            aaguid=str(verification.aaguid) # FIX REQ-07: Extraído da resposta criptográfica
        ))
        db.commit()
        
        del challenge_cache[current_user_id] 
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
# GESTÃO DE DISPOSITIVOS WEBAUTHN (REQ-10)
# ==========================================

@router.get("/webauthn/devices")
def list_webauthn_devices(current_user_id: str = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    REQ-10: Permite que o utilizador liste os seus dispositivos biométricos cadastrados.
    """
    devices = db.query(WebAuthnPasskey).filter(WebAuthnPasskey.user_id == current_user_id).all()
    
    return {
        "devices": [
            {
                "id": device.id,
                # Retorna apenas um prefixo da credencial por segurança, útil para UI
                "credential_id_prefix": device.credential_id[:16] + "...", 
                "sign_count": device.sign_count
            }
            for device in devices
        ]
    }

@router.delete("/webauthn/devices/{device_id}", dependencies=[Depends(validar_csrf)])
def revoke_webauthn_device(
    device_id: str, 
    request: Request,
    current_user_id: str = Depends(get_current_active_user), 
    db: Session = Depends(get_db)
):
    """
    REQ-10: Permite que o utilizador revogue/apague um dispositivo cadastrado.
    """
    # Procura o dispositivo garantindo que pertence ao utilizador atual
    device = db.query(WebAuthnPasskey).filter(
        WebAuthnPasskey.id == device_id,
        WebAuthnPasskey.user_id == current_user_id
    ).first()
    
    if not device:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado ou não tem permissão para o remover.")
        
    db.delete(device)
    
    # REQ-55/56: Registo da ação na auditoria
    db.add(AuditLog(
        user_id=current_user_id, 
        action="WEBAUTHN_DEVICE_REVOKED", 
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", ""),
        details=json.dumps({"device_id": device_id})
    ))
    
    db.commit()
    
    return {"message": "Dispositivo removido com sucesso."}

# ==========================================
# 5. ROTA DE REFRESH COM ROTAÇÃO (REQ-29/30)
# ==========================================
@router.post("/refresh", dependencies=[Depends(validar_csrf)])
def refresh_token_endpoint(request: Request, response: Response, db: Session = Depends(get_db)):
    old_refresh = request.cookies.get("refresh_token")
    if not old_refresh: raise HTTPException(status_code=401, detail="Refresh token ausente")
    
    # REQ-19: Hashear antes de procurar
    old_refresh_hash = hashlib.sha256(old_refresh.encode('utf-8')).hexdigest()
    session_db = db.query(RefreshSession).filter(RefreshSession.id == old_refresh_hash).first()
    
    if not session_db or session_db.is_revoked:
        if session_db:
            db.query(RefreshSession).filter(RefreshSession.user_id == session_db.user_id).update({"is_revoked": True})
            db.commit()
        raise HTTPException(status_code=403, detail="Sessão comprometida.")

    session_db.is_revoked = True
    new_refresh = sec.generate_refresh_token()
    new_refresh_hash = hashlib.sha256(new_refresh.encode('utf-8')).hexdigest()
    
    db.add(RefreshSession(
        id=new_refresh_hash, user_id=session_db.user_id, 
        expires_at=datetime.utcnow() + timedelta(days=7),
        ip_address=request.client.host, user_agent=request.headers.get("user-agent", "")
    ))
    db.commit()
    
    new_access, _ = sec.generate_access_token(session_db.user_id, request.client.host, request.headers.get("user-agent", ""), "new_session_id")
    csrf_token = generate_csrf_token()
    
    response.set_cookie(key="refresh_token", value=new_refresh, httponly=True, secure=True, samesite="strict", max_age=604800)
    response.set_cookie(key="csrf_token", value=csrf_token, httponly=False, secure=True, samesite="strict", max_age=604800)
    user = db.query(User).filter(User.id == session_db.user_id).first()
    return {"access_token": new_access, "csrf_token": csrf_token, "user": {"id": user.id, "username": user.username, "email": user.email, "is_totp_enabled": user.is_totp_enabled}}

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
        # REQ-19: Revogar com base no Hash!
        old_refresh_hash = hashlib.sha256(old_refresh.encode('utf-8')).hexdigest()
        db.query(RefreshSession).filter(RefreshSession.id == old_refresh_hash).update({"is_revoked": True})
        
    db.commit()
    response.delete_cookie("refresh_token")
    return {"message": "Logout seguro concluído"}

# ==========================================
# 7. GERENCIAMENTO DE SESSÕES ATIVAS (REQ-57)
# ==========================================

@router.get("/sessions")
def list_active_sessions(current_user_id: str = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Lista todas as sessões ativas do usuário autenticado.
    REQ-57: Permite visualizar o histórico de sessões ativas e gerenciá-las.
    """
    sessions = db.query(RefreshSession).filter(
        RefreshSession.user_id == current_user_id,
        RefreshSession.is_revoked == False,
        RefreshSession.expires_at > datetime.utcnow()
    ).all()
    
    return {
        "sessions": [
            {
                "id": session.id,
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "created_at": session.id[:8],  # Aproximadamente quando foi criada (baseado no UUID v7)
                "expires_at": session.expires_at.isoformat() if session.expires_at else None,
                "is_active": True
            }
            for session in sessions
        ]
    }

@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, current_user_id: str = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """
    Revoga uma sessão específica do usuário.
    REQ-57: Permite encerrar sessões individuais em outros dispositivos.
    """
    session = db.query(RefreshSession).filter(
        RefreshSession.id == session_id,
        RefreshSession.user_id == current_user_id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Sessão não encontrada")
    
    session.is_revoked = True
    db.add(AuditLog(user_id=current_user_id, action="SESSION_REVOKED", ip_address=session.ip_address))
    db.commit()
    
    return {"message": "Sessão encerrada com sucesso"}

@router.post("/sessions/revoke-all", dependencies=[Depends(validar_csrf)])
def revoke_all_sessions(request: Request, current_user_id: str = Depends(get_current_active_user), db: Session = Depends(get_db)):
    current_token = request.cookies.get("refresh_token")
    query = db.query(RefreshSession).filter(RefreshSession.user_id == current_user_id, RefreshSession.is_revoked == False)
    
    if current_token:
        current_token_hash = hashlib.sha256(current_token.encode('utf-8')).hexdigest()
        query = query.filter(RefreshSession.id != current_token_hash)
        
    query.update({"is_revoked": True})
    db.add(AuditLog(user_id=current_user_id, action="ALL_SESSIONS_REVOKED", ip_address=request.client.host))
    db.commit()
    return {"message": "Todas as outras sessões foram encerradas"}

# ==========================================
# 8. GESTÃO DE CONTA - TROCA DE SENHA (REQ-58)
# ==========================================

@router.post("/change-password", dependencies=[Depends(validar_csrf)])
def change_password_endpoint(
    req: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_active_user)
):
    """
    REQ-58: Permite ao utilizador alterar a sua senha com verificação da senha antiga,
    revalidação de complexidade, revogação global de sessões e alerta por e-mail.
    """
    user = db.query(User).filter(User.id == current_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilizador não encontrado")

    # 1. Valida se a senha atual está correta antes de permitir qualquer modificação
    if not sec.verify_password(req.old_password, user.password_hash):
        db.add(AuditLog(
            user_id=user.id, 
            action="PASSWORD_CHANGE_FAILED", 
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            details=json.dumps({"reason": "Senha atual incorreta"})
        ))
        db.commit()
        raise HTTPException(status_code=400, detail="A senha atual inserida está incorreta.")

    # 2. Impede que a nova senha seja igual à senha antiga
    if req.old_password == req.new_password:
        raise HTTPException(status_code=400, detail="A nova senha não pode ser idêntica à senha atual.")

    # 3. Atualiza o hash na base de dados utilizando Argon2id (configuração OWASP)
    user.password_hash = sec.hash_password(req.new_password)
    user.last_password_change = datetime.utcnow()
    
    # 4. Defesa de Alta Segurança: Revoga todas as sessões ativas (obriga a novo login em todos os dispositivos)
    db.query(RefreshSession).filter(RefreshSession.user_id == current_user_id).update({"is_revoked": True})
    
    # 5. REQ-55/56: Registo do sucesso na auditoria
    db.add(AuditLog(
        user_id=current_user_id,
        action="PASSWORD_CHANGED",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", ""),
        details=json.dumps({"status": "success"})
    ))
    db.commit()

    # 6. Notificação imediata por e-mail
    if user.email:
        enviar_email_notificacao(
            user.email,
            "Segurança SecureSign: Senha alterada",
            f"A senha da sua conta foi alterada com sucesso em {datetime.utcnow().isoformat()} UTC a partir do IP {request.client.host}.\n\nSe não realizou esta operação, por favor contacte imediatamente o administrador do sistema."
        )

    return {"message": "Senha alterada com sucesso. Todas as sessões ativas foram encerradas por motivos de segurança."}