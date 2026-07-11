from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

payload = {
    'username': 'teste',
    'email': 'teste@example.com',
    'password': 'SenhaForte!123',
    'confirm_password': 'SenhaForte!123'
}

response = client.post('/api/v1/auth/register', json=payload, headers={'Origin': 'http://127.0.0.1:3000'})
print('status', response.status_code)
print('headers', {k:v for k,v in response.headers.items() if k.lower().startswith('access-control') or k.lower().startswith('content-type')})
print('body', response.text)
