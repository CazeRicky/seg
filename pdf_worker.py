import sys
import json
import base64
import hashlib
import io
from datetime import datetime

# Importações perigosas de processamento de PDF ficam APENAS aqui
from pyhanko.sign import signers
from pyhanko.pdf_utils import text
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

def main():
    try:
        # 1. Lê os dados recebidos via STDIN de forma segura (não aparece no ps aux)
        input_data = sys.stdin.read()
        payload = json.loads(input_data)
        
        # 2. Desempacota os dados
        pdf_bytes = base64.b64decode(payload['pdf_base64'])
        priv_pem = payload['priv_pem']
        cert_pem = payload['cert_pem']
        user_name = payload['user_name']
        x, y = payload['coords']
        page = payload['page']
        doc_hash = payload['doc_hash']
        sig_id = payload['sig_id']

        # 3. Prepara o motor do PyHanko
        signer = signers.SimpleSigner.load_pem_pem(
            priv_pem.encode('utf-8'), cert_pem.encode('utf-8')
        )
        pdf_stream = io.BytesIO(pdf_bytes)
        out_stream = io.BytesIO()
        writer = IncrementalPdfFileWriter(pdf_stream)

        # 4. Formata o selo visual
        data_atual = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        stamp_text_content = (
            f"Assinado por: {user_name}\n"
            f"Data: {data_atual}\n"
            f"Hash: {doc_hash[:16]}...{doc_hash[-16:]}\n"
            f"ID: {sig_id}"
        )
        stamp_style = text.TextStampStyle(
            stamp_text=stamp_text_content,
            text_box_style=text.TextBoxStyle(font=text.GenericFontFamily.HELVETICA, font_size=8)
        )

        append_signature_field(
            writer, 
            SigFieldSpec('Assinatura_UABJ', box=(x, y, x + 250, y + 60), on_page=page - 1)
        )

        signers.sign_pdf(
            writer, signers.PdfSignatureMetadata(field_name='Assinatura_UABJ'),
            signer=signer,
            out_stream=out_stream,
            appearance_text_params={'url': 'https://front-oficial.com/verificar'},
            style=stamp_style
        )

        # 5. Recupera os bytes finais e o novo hash
        signed_bytes = out_stream.getvalue()
        new_hash = hashlib.sha256(signed_bytes).hexdigest()
        
        # 6. Devolve o resultado via STDOUT para a API
        result = {
            "status": "success",
            "signed_pdf_base64": base64.b64encode(signed_bytes).decode('utf-8'),
            "new_hash": new_hash
        }
        print(json.dumps(result))

    except Exception as e:
        # Se algo falhar (ex: PDF corrompido), o worker devolve o erro e encerra em segurança
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()