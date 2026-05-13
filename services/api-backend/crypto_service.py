import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoService:
    def __init__(self):
        # MOCKING: Giả lập một khóa DEK 256-bit
        # Khi DevOps làm xong Vault, ta sẽ xóa dòng này.
        self.mock_dek = AESGCM.generate_key(bit_length=256)

    def get_dek_from_vault(self):
        # TODO: Viết code dùng thư viện 'hvac' gọi API sang Vault lấy khóa DEK thật
        # URL mẫu: http://sme-vault:8200/v1/transit/keys/backend-db-enc
        return self.mock_dek

    def encrypt_data(self, plaintext: str) -> dict:
        dek = self.get_dek_from_vault()
        aesgcm = AESGCM(dek)
        
        # Tạo Nonce ngẫu nhiên 12 bytes (Bắt buộc cho chuẩn GCM, không được tái sử dụng)
        nonce = os.urandom(12) 
        
        # Mã hóa
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex()
        }