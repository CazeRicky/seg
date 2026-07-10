import sys
import json
import base64
import hashlib
import io
from datetime import datetime

from pyhanko.sign import signers
from pyhanko.pdf_utils import text
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

# FIX REQ-50: Importações para abrir e validar a matemática do PDF
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature

def main():
    try:
        input_data = sys.stdin.read()
        payload = json.loads(input_data)
        action = payload.get("action", "sign") # NOVO: Roteamento de ação

        pdf_bytes = base64.b64decode(payload['pdf_base64'])

        if action == "sign":
            priv_pem = payload['priv_pem']
            cert_pem = payload['cert_pem']
            user_name = payload['user_name']
            x, y = payload['coords']
            page = payload['page']
            doc_hash = payload['doc_hash']
            sig_id = payload['sig_id']

            signer = signers.SimpleSigner.load_pem_pem(priv_pem.encode('utf-8'), cert_pem.encode('utf-8'))
            pdf_stream = io.BytesIO(pdf_bytes)
            out_stream = io.BytesIO()
            writer = IncrementalPdfFileWriter(pdf_stream)

            data_atual = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            stamp_text_content = f"Assinado por: {user_name}\nData: {data_atual}\nHash: {doc_hash[:16]}...{doc_hash[-16:]}\nID: {sig_id}"
            stamp_style = text.TextStampStyle(stamp_text=stamp_text_content, text_box_style=text.TextBoxStyle(font=text.GenericFontFamily.HELVETICA, font_size=8))

            append_signature_field(writer, SigFieldSpec('Assinatura_UABJ', box=(x, y, x + 250, y + 60), on_page=page - 1))
            signers.sign_pdf(writer, signers.PdfSignatureMetadata(field_name='Assinatura_UABJ'), signer=signer, out_stream=out_stream, appearance_text_params={'url': 'https://front-oficial.com/verificar'}, style=stamp_style)

            signed_bytes = out_stream.getvalue()
            new_hash = hashlib.sha256(signed_bytes).hexdigest()
            
            print(json.dumps({"status": "success", "signed_pdf_base64": base64.b64encode(signed_bytes).decode('utf-8'), "new_hash": new_hash}))

        elif action == "verify":
            # FIX REQ-50: Lógica de validação em ambiente Sandbox
            pdf_stream = io.BytesIO(pdf_bytes)
            reader = PdfFileReader(pdf_stream)
            
            signatures = reader.embedded_signatures
            if not signatures:
                print(json.dumps({"status": "error", "message": "Nenhuma assinatura criptográfica embutida (X.509) foi encontrada no PDF."}))
                return
                
            # Extrai e valida a primeira assinatura do documento
            sig = signatures[0]
            status = validate_pdf_signature(sig)
            
            print(json.dumps({
                "status": "success",
                "valid": status.intact and status.valid, # Intact = Arquivo não modificado. Valid = Chaves batem.
                "signer": status.signer_info.signer_cert.subject.human_friendly if status.signer_info else "Desconhecido"
            }))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()