from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import declarative_base
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True) #uuid v4
    username = Column(String, unique=True, index=True)
    password_hash = Column(String) #defesa:REQ-02.so guarda hash argon2
    #defesa:REQ-45.cada utilizador tem um par RSA2048 gerado no registo p assinar os PDFs
    rsa_pub = Column(Text) 
    rsa_priv_encrypted = Column(Text) #criptografado c a master key do sistema
    
    #defesa:REQ-12.segredo do google authenticator guardado aqui
    is_totp_enabled = Column(Boolean, default=False)
    totp_secret = Column(String)
    backup_codes = Column(Text) #defesa:REQ-14.hashes dos codigos de backup
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)

class WebAuthnPasskey(Base):
    __tablename__ = "webauthn_passkeys"
    #defesa:REQ-07.tabela especifica p guardar as biometrias/passkeys do FIDO2
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"))
    credential_id = Column(String, unique=True, index=True)
    public_key = Column(String)
    sign_count = Column(Integer, default=0) #defesa:REQ-08.evita clonagem de dispositivo

class RefreshSession(Base):
    __tablename__ = "refresh_sessions"
    #defesa:REQ-19,REQ-28.tabela q controla sessoes de 7 dias via uuid opaco
    id = Column(String, primary_key=True) #uuid v7
    user_id = Column(String, ForeignKey("users.id"))
    expires_at = Column(DateTime)
    is_revoked = Column(Boolean, default=False)
    ip_address = Column(String)
    user_agent = Column(String)

class DenylistToken(Base):
    __tablename__ = "denylist_tokens"
    #defesa:REQ-21.invalida JWTs ativos na hora do logout
    jti = Column(String, primary_key=True) #id unico do token JWT
    expires_at = Column(DateTime) #apaga do banco qd o tempo original do token bater

class AuditLog(Base):
    __tablename__ = "audit_logs"
    #defesa:REQ-55,REQ-56.tabela imutavel(append-only) q rastreia absolutamente tudo
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, index=True)
    action = Column(String) #ex:LOGIN_SUCCESS, PDF_SIGNED
    ip_address = Column(String)
    user_agent = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    details = Column(Text) #json c metadados extras da acao

class DocumentSignature(Base):
    __tablename__ = "document_signatures"
    #defesa:REQ-48.nunca guarda o PDF! guarda so o rastro matematico dele
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id"))
    doc_hash_orig = Column(String) #hash sha256 do doc original
    doc_hash_signed = Column(String) #hash sha256 do doc final
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
    coord_x = Column(Integer) #defesa:REQ-49.coord do selo visual
    coord_y = Column(Integer)
    page = Column(Integer)