from fastapi import APIRouter, Request, Response, HTTPException, UploadFile, File, Depends, Form
from sqlalchemy.orm import Session
import uuid
from datetime import datetime

from slowapi import Limiter
from slowapi.util import get_remote_address

from database import get_db
from models import User, DocumentSignature
from pdf_engine import PDFSecurityEngine
from security_engine import SecurityEngine
from dependencies import validar_csrf, get_current_active_user

router = APIRouter(prefix="/api/v1/pdf", tags=["Documentos"])
pdf_sec = PDFSecurityEngine()
sec = SecurityEngine()
limiter = Limiter(key_func=get_remote_address)

# ==========================================
# ROTA 1: ASSINAR DOCUMENTO (REQ-48 e REQ-49)
# ==========================================
@router.post("/sign", dependencies=[Depends(validar_csrf)])
async def sign_pdf_endpoint(
    request: Request,
    file: UploadFile = File(...),
    coord_x: int = Form(100),
    coord_y: int = Form(100),
    page: int = Form(1), # NOVO: Puxa o número da página do formulário
    db: Session = Depends(get_db),
    current_user_id: str = Depends(get_current_active_user),
):
    user = db.query(User).filter(User.id == current_user_id).first()
    
    if not user.rsa_priv_encrypted:
        raise HTTPException(status_code=400, detail="Utilizador não possui certificado digital.")

    # 1. Valida o ficheiro e obtém os bytes e o hash original
    pdf_bytes, orig_hash = await pdf_sec.validate_and_hash(file)

    # 2. Desencripta a chave privada na RAM (REQ-45)
    priv_pem = sec.decrypt_private_key(user.rsa_priv_encrypted)
    
    # 3. NOVO: Geramos o ID da Assinatura antes de assinar, para o podermos injetar no selo visual!
    sig_id = str(uuid.uuid4())
    
    # 4. Executa a assinatura real (REQ-46 e REQ-47)
    signed_bytes, signed_hash = pdf_sec.sign_document(
        pdf_bytes=pdf_bytes, 
        priv_pem=priv_pem, 
        cert_pem=user.rsa_pub,
        user_name=user.username,
        coords=(coord_x, coord_y),
        page=page,             # Passa a página pedida
        doc_hash=orig_hash,    # Passa o hash original
        sig_id=sig_id          # Passa o UUID gerado
    )

    # 5. Defesa: REQ-48 e REQ-49. Registo de Auditoria
    signature_record = DocumentSignature(
        id=sig_id, # Usamos o ID que injetámos no selo
        user_id=user.id,
        doc_hash_orig=orig_hash,
        doc_hash_signed=signed_hash,
        timestamp=datetime.utcnow(),
        ip_address=request.client.host,
        coord_x=coord_x, coord_y=coord_y, 
        page=page # NOVO: Regista a página real na base de dados (e não apenas um "1" fixo)
    )
    db.add(signature_record)
    db.commit()

    # Retorna o ficheiro assinado diretamente para o frontend fazer download (REQ-54)
    return Response(
        content=signed_bytes, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=assinado_{file.filename}"}
    )

# ==========================================
# ROTA 2: VERIFICAÇÃO PÚBLICA (REQ-50 a REQ-54)
# ==========================================
@router.post("/verify", dependencies=[Depends(validar_csrf)])
@limiter.limit("5/minute")
async def verify_pdf_endpoint(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Defesa: REQ-50 e REQ-54 - Validação Matemática e Isolada do Arquivo Físico.
    """
    pdf_bytes, current_hash = await pdf_sec.validate_and_hash(file)

    # 1. FIX REQ-50: Envia o PDF para o Sandbox validar matematicamente as chaves X.509
    verification_result = pdf_sec.verify_document(pdf_bytes)

    if not verification_result.get("valid"):
        raise HTTPException(status_code=400, detail={"code": "DOC_004", "message": "O documento possui uma assinatura corrompida ou foi adulterado após a assinatura."})

    # 2. Defesa em Profundidade: Cruzamos a validação estrutural com os nossos registos (Opcional, mas altíssimo nível de segurança)
    sig_record = db.query(DocumentSignature).filter(DocumentSignature.doc_hash_signed == current_hash).first()
    
    if sig_record:
        return {
            "status": "VALID",
            "message": "Documento íntegro e assinatura criptográfica matemática (X.509) autêntica.",
            "signer": verification_result.get("signer", "Desconhecido"),
            "signed_at": sig_record.timestamp.isoformat(),
            "original_hash": sig_record.doc_hash_orig,
            "database_verified": True
        }
    else:
        # Se o ficheiro é válido matematicamente mas não está na nossa base (ex: assinado noutra plataforma)
        return {
            "status": "PARTIAL_VALID",
            "message": "A assinatura estrutural é válida, mas não existe registo de auditoria deste documento na nossa base de dados.",
            "signer": verification_result.get("signer", "Desconhecido"),
            "database_verified": False
        }