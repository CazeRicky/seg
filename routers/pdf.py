from fastapi import APIRouter, Request, Response, HTTPException, UploadFile, File, Depends, Form
from sqlalchemy.orm import Session
import uuid
from datetime import datetime

from database import get_db
from models import User, DocumentSignature
from pdf_engine import PDFSecurityEngine
from security_engine import SecurityEngine
from dependencies import validar_csrf

router = APIRouter(prefix="/api/v1/pdf", tags=["Documentos"])
pdf_sec = PDFSecurityEngine()
sec = SecurityEngine()

# Dependência simulada para extrair o utilizador autenticado do token JWT
def get_current_user_id():
    return "uuid-do-banco" # No projeto final, isto deve descodificar o JWT e devolver o ID

# ==========================================
# ROTA 1: ASSINAR DOCUMENTO (REQ-48 e REQ-49)
# ==========================================
@router.post("/sign", dependencies=[Depends(validar_csrf)])
async def sign_pdf_endpoint(
    request: Request,
    file: UploadFile = File(...), 
    coord_x: int = Form(100), 
    coord_y: int = Form(100),
    db: Session = Depends(get_db)
):
    user_id = get_current_user_id()
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user.rsa_priv_encrypted:
        raise HTTPException(status_code=400, detail="Utilizador não possui certificado digital.")

    # 1. Valida o ficheiro e obtém os bytes e o hash original
    pdf_bytes, orig_hash = await pdf_sec.validate_and_hash(file)

    # 2. Desencripta a chave privada na RAM (REQ-45)
    priv_pem = sec.decrypt_private_key(user.rsa_priv_encrypted)
    
    # 3. Executa a assinatura real (REQ-46 e REQ-47)
    signed_bytes, signed_hash = pdf_sec.sign_document(
        pdf_bytes=pdf_bytes, 
        priv_pem=priv_pem, 
        cert_pem=user.rsa_pub, # Usamos o campo rsa_pub para guardar o certificado X509
        user_name=user.username,
        coords=(coord_x, coord_y)
    )

    # 4. Defesa: REQ-48 e REQ-49. Registo de Auditoria
    signature_record = DocumentSignature(
        id=str(uuid.uuid4()),
        user_id=user.id,
        doc_hash_orig=orig_hash,
        doc_hash_signed=signed_hash,
        timestamp=datetime.utcnow(),
        ip_address=request.client.host,
        coord_x=coord_x, coord_y=coord_y, page=1
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
@router.post("/verify")
# Aqui também deve colocar o @limiter.limit("5/minute") para cumprir o REQ-53!
async def verify_pdf_endpoint(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Defesa: REQ-54 - O PDF é processado em memória e nunca é guardado no disco.
    """
    pdf_bytes, current_hash = await pdf_sec.validate_and_hash(file)

    # Defesa: REQ-51. Compara o hash atual com a base de dados
    sig_record = db.query(DocumentSignature).filter(DocumentSignature.doc_hash_signed == current_hash).first()
    
    if sig_record:
        # Defesa: REQ-52
        return {
            "status": "VALID",
            "message": "Documento íntegro e assinatura autêntica.",
            "signed_at": sig_record.timestamp.isoformat(),
            "original_hash": sig_record.doc_hash_orig
        }
    else:
        # Se o hash não estiver na base de dados, significa que foi adulterado ou nunca foi assinado aqui
        raise HTTPException(status_code=400, detail={"code": "DOC_004", "message": "Documento adulterado ou assinatura não encontrada."})