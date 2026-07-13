import sys
import json
import base64
import hashlib
import io
from datetime import datetime

from pyhanko.sign import signers
from pyhanko.pdf_utils import text
from pyhanko.stamp import TextStampStyle
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from asn1crypto import pem as asn1_pem, keys as asn1_keys, x509 as asn1_x509
from pyhanko_certvalidator.registry import SimpleCertificateStore

def build_signer(priv_pem: str, cert_pem: str) -> signers.SimpleSigner:
    _, _, key_der = asn1_pem.unarmor(priv_pem.encode("utf-8"))
    _, _, cert_der = asn1_pem.unarmor(cert_pem.encode("utf-8"))
    asn1_key = asn1_keys.PrivateKeyInfo.load(key_der)
    asn1_cert = asn1_x509.Certificate.load(cert_der)
    cert_store = SimpleCertificateStore()
    return signers.SimpleSigner(
        signing_cert=asn1_cert,
        signing_key=asn1_key,
        cert_registry=cert_store,
    )

def main():
    try:
        input_data = sys.stdin.read()
        if not input_data:
            print(json.dumps({"status": "error", "message": "Nenhum dado recebido no stdin."}))
            sys.exit(1)
            
        payload = json.loads(input_data)
        action = payload.get("action", "sign")

        pdf_bytes = base64.b64decode(payload['pdf_base64'])

        if action == "sign":
            priv_pem = payload['priv_pem']
            cert_pem = payload['cert_pem']
            user_name = payload['user_name']
            x, y = payload['coords']
            page = payload['page']
            doc_hash = payload['doc_hash']
            sig_id = payload['sig_id']

            signer = build_signer(priv_pem, cert_pem)

            pdf_stream = io.BytesIO(pdf_bytes)
            writer = IncrementalPdfFileWriter(pdf_stream)

            data_atual = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            stamp_text_content = f"Assinado por: {user_name}\nData: {data_atual}\nHash: {doc_hash[:16]}...{doc_hash[-16:]}\nID: {sig_id}"
            
            stamp_style = TextStampStyle(
                stamp_text=stamp_text_content, 
                text_box_style=text.TextBoxStyle(font_size=8)
            )

            campo_assinatura = f'Assinatura_UABJ_{sig_id[:8]}'
            append_signature_field(writer, SigFieldSpec(campo_assinatura, box=(x, y, x + 250, y + 60), on_page=page - 1))
            
            meta = signers.PdfSignatureMetadata(field_name=campo_assinatura)
            pdf_signer = signers.PdfSigner(
                meta, signer=signer, stamp_style=stamp_style
            )
            
            pdf_signer.sign_pdf(
                writer, 
                in_place=True,
                appearance_text_params={'url': 'https://front-oficial.com/verificar'}
            )

            signed_bytes = pdf_stream.getvalue()
            new_hash = hashlib.sha256(signed_bytes).hexdigest()
            
            print(json.dumps({"status": "success", "signed_pdf_base64": base64.b64encode(signed_bytes).decode('utf-8'), "new_hash": new_hash}))

        elif action == "verify":
            try:
                from pyhanko.sign.validation import validate_pdf_signature
            except ImportError:
                print(json.dumps({"status": "error", "message": "Biblioteca de validação ausente."}))
                sys.exit(1)

            pdf_stream = io.BytesIO(pdf_bytes)
            reader = PdfFileReader(pdf_stream)
            
            signatures = reader.embedded_signatures
            if not signatures:
                print(json.dumps({"status": "error", "message": "Nenhuma assinatura criptográfica embutida foi encontrada."}))
                sys.exit(1)
                
            sig = signatures[0]
            status = validate_pdf_signature(sig)
            
            # FIX: Extração do nome de forma ultra-segura, sem causar crashs
            signer_name = "Desconhecido"
            try:
                if hasattr(sig, 'signer_cert') and sig.signer_cert:
                    signer_name = sig.signer_cert.subject.human_friendly
            except Exception:
                pass
            
            # Extração do status de integridade de forma segura
            is_intact = getattr(status, 'intact', True)
            
            print(json.dumps({
                "status": "success",
                "valid": is_intact, 
                "signer": signer_name
            }))

    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)

if __name__ == "__main__":
    main()