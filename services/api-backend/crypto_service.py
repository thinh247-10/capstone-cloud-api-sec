import hvac
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoService:
    def __init__(self):
        self.client = hvac.Client(
            url=os.getenv("VAULT_URL", "http://localhost:8200"),
            token=os.getenv("VAULT_TOKEN", "root") 
        )

    def get_dek_from_vault(self):
        # Sử dụng tính năng Transit của Vault để lấy một khóa DEK
        generate_key_response = self.client.secrets.transit.generate_data_key(
            name='backend-db-enc', 
            key_type='plaintext',
            mount_point='transit',
        )
        # Vault trả về khóa dưới dạng Base64, cần decode ra bytes
        import base64
        return base64.b64decode(generate_key_response['data']['plaintext'])

    def encrypt_data(self, plaintext: str) -> dict:
        #Lấy dek từ Vault theo, logic AES-GCM
        dek = self.get_dek_from_vault()
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }