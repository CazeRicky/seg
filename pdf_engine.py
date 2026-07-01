import hashlib
import io
from fastapi import UploadFile, HTTPException
from datetime import datetime

# Importações do PyHanko (O Boss da Assinatura)
from pyhanko.sign import signers
from pyhanko.pdf_utils import text, images
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

class PDFSecurityEngine:
    async def validate_and_hash(self, file: UploadFile) -> tuple[bytes, str]:
        # Lemos o ficheiro uma única vez e mantemos em memória
        contents = await file.read(20 * 1024 * 1024 + 1)
        
        # Defesa: REQ-61
        if len(contents) > 20 * 1024 * 1024:
            raise HTTPException(status_code=400, detail={"code": "DOC_001", "message": "Limite de 20MB excedido"})
            
        # Defesa: REQ-60
        if not contents.startswith(b"%PDF-"):
            raise HTTPException(status_code=400, detail={"code": "DOC_002", "message": "O ficheiro não é um PDF válido"})
            
        # Defesa: REQ-63
        if b"/JS" in contents or b"/JavaScript" in contents:
            raise HTTPException(status_code=400, detail={"code": "DOC_003", "message": "PDF contém JavaScript malicioso"})
            
        doc_hash = hashlib.sha256(contents).hexdigest()
        return contents, doc_hash

    def sign_document(self, pdf_bytes: bytes, priv_pem: str, cert_pem: str, user_name: str, coords: tuple) -> tuple[bytes, str]:
        """
        Defesa: REQ-46 e REQ-47. Injeta a assinatura ISO 32000 com selo visual.
        """
        # Carrega a chave e o certificado para a memória usando PyHanko
        signer = signers.SimpleSigner.load_pem_pem(
            priv_pem.encode('utf-8'), cert_pem.encode('utf-8')
        )

        pdf_stream = io.BytesIO(pdf_bytes)
        out_stream = io.BytesIO()
        writer = IncrementalPdfFileWriter(pdf_stream)

        # Defesa: REQ-47. Configura o selo visual (Página 1, coordenadas X,Y)
        x, y = coords
        stamp_style = text.TextStampStyle(
            stamp_text=f"Assinado por: {user_name}\nData: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            text_box_style=text.TextBoxStyle(font=text.GenericFontFamily.HELVETICA)
        )

        # Prepara a assinatura
        signers.sign_pdf(
            writer, signers.PdfSignatureMetadata(field_name='Assinatura_UABJ'),
            signer=signer,
            out_stream=out_stream,
            appearance_text_params={'url': 'https://front-oficial.com/verificar'},
            style=stamp_style,
            box=(x, y, x + 200, y + 50) # Tamanho da caixa da assinatura
        )

        # Pega nos novos bytes assinados e gera o novo hash
        signed_bytes = out_stream.getvalue()
        new_hash = hashlib.sha256(signed_bytes).hexdigest()
        
        return signed_bytes, new_hash