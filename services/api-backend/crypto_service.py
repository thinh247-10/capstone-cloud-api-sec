import hvac
import os
import base64

class CryptoService:
    def __init__(self):
        self.client = hvac.Client(
            url=os.getenv("VAULT_URL", "http://localhost:8200"),
            token=os.getenv("VAULT_TOKEN", "root") 
        )

    def encrypt_data(self, plaintext: str) -> dict:
        """Gửi thẳng dữ liệu cho Vault Transit Engine mã hóa"""
        # Vault yêu cầu plaintext phải được encode Base64 trước khi gửi
        encoded_text = base64.b64encode(plaintext.encode('utf-8')).decode('utf-8')
        
        # Gọi Vault mã hóa
        encrypt_response = self.client.secrets.transit.encrypt_data(
            name='backend-db-enc',
            plaintext=encoded_text,
            mount_point='transit',
        )
        
        # Vault trả về định dạng: vault:v1:xxxxxxxxx
        ciphertext = encrypt_response['data']['ciphertext']
        
        return {
            "nonce": "vault_managed", # Vault tự quản lý nonce, mình không cần sinh nữa
            "ciphertext": ciphertext
        }