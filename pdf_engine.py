import hashlib
import json
import base64
import subprocess
import os
from fastapi import UploadFile, HTTPException

class PDFSecurityEngine:
    async def validate_and_hash(self, file: UploadFile) -> tuple[bytes, str]:
        # Validação inicial em memória
        contents = await file.read(20 * 1024 * 1024 + 1)
        
        if len(contents) > 20 * 1024 * 1024:
            raise HTTPException(status_code=400, detail={"code": "DOC_001", "message": "Limite de 20MB excedido"})
            
        if not contents.startswith(b"%PDF-"):
            raise HTTPException(status_code=400, detail={"code": "DOC_002", "message": "O ficheiro não é um PDF válido"})
            
        if b"/JS" in contents or b"/JavaScript" in contents:
            raise HTTPException(status_code=400, detail={"code": "DOC_003", "message": "PDF contém JavaScript malicioso"})
            
        doc_hash = hashlib.sha256(contents).hexdigest()
        return contents, doc_hash

    def sign_document(self, pdf_bytes: bytes, priv_pem: str, cert_pem: str, user_name: str, coords: tuple, page: int, doc_hash: str, sig_id: str) -> tuple[bytes, str]:
        """
        Defesa: REQ-62 - O processamento do PDF é atirado para um processo isolado.
        """
        payload = {
            "pdf_base64": base64.b64encode(pdf_bytes).decode('utf-8'),
            "priv_pem": priv_pem,
            "cert_pem": cert_pem,
            "user_name": user_name,
            "coords": coords,
            "page": page,
            "doc_hash": doc_hash,
            "sig_id": sig_id
        }

        # Caminho absoluto para garantir que encontra o ficheiro
        worker_path = os.path.join(os.path.dirname(__file__), "pdf_worker.py")
        
        try:
            # Inicia o processo isolado.
            # Dica extra: Em Linux de produção podes substituir o comando ["python", worker_path] 
            # por ["bwrap", "--unshare-all", "--ro-bind", "/", "/", "python", worker_path] para sandbox total.
            process = subprocess.Popen(
                ["python", worker_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Comunica com o processo e define um TIMEOUT (mata exploits de ciclos infinitos)
            stdout, stderr = process.communicate(input=json.dumps(payload), timeout=10)
            
            if process.returncode != 0:
                raise HTTPException(status_code=500, detail={"code": "DOC_005", "message": "Falha crítica no isolamento do PDF."})

            result = json.loads(stdout)
            
            if result.get("status") == "error":
                raise HTTPException(status_code=500, detail={"code": "DOC_006", "message": f"Erro interno ao assinar: {result.get('message')}"})

            signed_bytes = base64.b64decode(result["signed_pdf_base64"])
            new_hash = result["new_hash"]
            
            return signed_bytes, new_hash

        except subprocess.TimeoutExpired:
            process.kill() # Mata o processo imediatamente se ultrapassar os 10 segundos
            raise HTTPException(status_code=408, detail={"code": "DOC_007", "message": "Timeout ao processar PDF (possível bomba de descompressão ou ficheiro demasiado pesado)."})
        except Exception as e:
            raise HTTPException(status_code=500, detail={"code": "DOC_008", "message": "Erro na ponte de comunicação de assinatura."})
    def verify_document(self, pdf_bytes: bytes) -> dict:
        """
        Defesa: REQ-50 - Consulta estrutural (criptográfica) de assinaturas X.509 em Sandbox
        """
        payload = {
            "action": "verify",
            "pdf_base64": base64.b64encode(pdf_bytes).decode('utf-8')
        }
        worker_path = os.path.join(os.path.dirname(__file__), "pdf_worker.py")
        
        try:
            process = subprocess.Popen(["python", worker_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(input=json.dumps(payload), timeout=10)
            
            if process.returncode != 0:
                raise HTTPException(status_code=500, detail={"code": "DOC_005", "message": "Falha crítica no isolamento do PDF."})
                
            result = json.loads(stdout)
            if result.get("status") == "error":
                raise HTTPException(status_code=400, detail={"code": "DOC_004", "message": result.get("message")})
                
            return result
        except subprocess.TimeoutExpired:
            process.kill()
            raise HTTPException(status_code=408, detail={"code": "DOC_007", "message": "Timeout ao processar PDF."})