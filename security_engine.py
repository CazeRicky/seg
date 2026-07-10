import os
import time
import jwt
import pyotp
import hashlib
from datetime import datetime, timedelta
from passlib.hash import argon2
from uuid7 import uuid7
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.fernet import Fernet

class SecurityEngine:
    def __init__(self):
        # Defesa: REQ-02. Configuração do Argon2id (OWASP: memory=64MB, iterations=3, parallelism=4)
        self.ph = argon2.using(time_cost=3, memory_cost=65536, parallelism=4, type="ID")
        
        # Par de chaves RSA do SISTEMA para assinar e validar os tokens JWT
        self.jwt_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwt_pub = self.jwt_priv.public_key()
        
        self.jwt_priv_pem = self.jwt_priv.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )
        
        self.jwt_pub_pem = self.jwt_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # ==========================================
    # GESTÃO DE SENHAS
    # ==========================================
    def hash_password(self, pwd: str) -> str:
        return self.ph.hash(pwd)

    def verify_password(self, pwd: str, hash_pwd: str) -> bool:
        try: 
            return self.ph.verify(pwd, hash_pwd)
        except: 
            return False

    # ==========================================
    # GESTÃO DE 2FA (TOTP)
    # ==========================================
    def generate_totp_secret(self) -> str:
        # Defesa: REQ-12. Gera segredo de 160 bits (32 chars base32)
        return pyotp.random_base32(length=32)

    def verify_totp(self, secret: str, code: str) -> bool:
        # Defesa: REQ-11. Valida a janela de 30s atual e +- 1 janela
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    # ==========================================
    # CRIPTOGRAFIA DE PDF E ASSINATURAS
    # ==========================================
    def encrypt_private_key(self, priv_pem_str: str) -> str:
        # Defesa: REQ-45. Encripta a chave com a Master Key do sistema
        master_key = os.getenv("MASTER_KEY")
        if not master_key: 
            raise ValueError("ERRO CRÍTICO: MASTER_KEY ausente no .env")
        f = Fernet(master_key.encode('utf-8'))
        return f.encrypt(priv_pem_str.encode('utf-8')).decode('utf-8')

    def decrypt_private_key(self, encrypted_priv_pem_str: str) -> str:
        master_key = os.getenv("MASTER_KEY")
        if not master_key: 
            raise ValueError("ERRO CRÍTICO: MASTER_KEY ausente no .env")
        f = Fernet(master_key.encode('utf-8'))
        return f.decrypt(encrypted_priv_pem_str.encode('utf-8')).decode('utf-8')

    def generate_user_rsa_keys(self, user_name: str):
        # Defesa: REQ-45. Gera par RSA-2048
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        
        # Gera um certificado X.509 autoassinado na hora (Necessário para o PyHanko assinar PDFs)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user_name)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)\
            .public_key(pub).serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
            .sign(priv, hashes.SHA256())

        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Retorna a chave privada já encriptada e o certificado público em PEM
        return self.encrypt_private_key(priv_pem.decode('utf-8')), cert_pem.decode('utf-8')

    # ==========================================
    # GESTÃO DE TOKENS JWT E SESSÕES
    # ==========================================
    def generate_access_token(self, user_id: str, ip: str, ua: str, session_id: str) -> tuple:
        # Defesa: REQ-18. Tempo de vida curto (15mins)
        exp = datetime.utcnow() + timedelta(minutes=15)
        
        # Gera o ID único do token (JTI) com UUIDv7 (Ordenável)
        jti = str(uuid7())
        
        # Defesa: REQ-26 e REQ-27. Hashes para ancorar o token à rede e dispositivo
        ip_hash = hashlib.sha256(ip.encode('utf-8')).hexdigest()
        ua_hash = hashlib.sha256(ua.encode('utf-8')).hexdigest()
        
        payload = {
            "sub": str(user_id), 
            "jti": jti, 
            "iat": datetime.utcnow(), 
            "exp": exp, 
            "ip_hash": ip_hash, 
            "ua_hash": ua_hash, 
            "session_id": session_id
        }
        
        # Defesa: REQ-17. Assinatura RS256
        token = jwt.encode(payload, self.jwt_priv_pem, algorithm="RS256")
        
        return token, jti

    def generate_refresh_token(self) -> str:
        # Defesa: REQ-19. Gera um UUID opaco v7 (ordenável) para a sessão longa
        return str(uuid7())
    def encrypt_data(self, data: str) -> str:
        # Usado para encriptar o TOTP Secret (REQ-12)
        master_key = os.getenv("MASTER_KEY")
        f = Fernet(master_key.encode('utf-8'))
        return f.encrypt(data.encode('utf-8')).decode('utf-8')

    def decrypt_data(self, encrypted_data: str) -> str:
        # Usado para desencriptar o TOTP Secret (REQ-12)
        master_key = os.getenv("MASTER_KEY")
        f = Fernet(master_key.encode('utf-8'))
        return f.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

# Instância singleton que mantém as mesmas chaves RSA durante a execução do processo
sec = SecurityEngine()
