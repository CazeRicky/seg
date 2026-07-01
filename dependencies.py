from fastapi import Request, HTTPException, status

def validar_csrf(request: Request):
    """
    Defesa: REQ-65 - Verificação de Origin/Referer contra ataques CSRF
    """
    origem = request.headers.get("origin")
    referer = request.headers.get("referer")
    
    # As origens exatas do seu frontend (devem coincidir com as permitidas no CORS do main.py)
    origens_permitidas = ["https://front-oficial.com", "http://localhost:3000"]
    
    origem_cliente = origem or referer
    
    if not origem_cliente:
        # Se o navegador não enviou Origin nem Referer em rotas de mutação (POST/PUT/DELETE), bloqueamos.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail={"code": "SEC_001", "message": "Tentativa de CSRF bloqueada: Origem desconhecida"}
        )
        
    # Limpar a barra final (trailing slash) do referer, se existir
    if origem_cliente.endswith('/'):
        origem_cliente = origem_cliente[:-1]
        
    if origem_cliente not in origens_permitidas:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "SEC_002", "message": "Tentativa de CSRF bloqueada: Origem não autorizada"}
        )