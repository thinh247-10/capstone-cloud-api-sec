import time
import base64
import hashlib
import jwt
import json
from fastapi import Request, HTTPException

# Cache lưu trữ các 'jti' đã sử dụng để chống Replay Attack (Nên thay bằng Redis trên Production)
JTI_CACHE = set()

class DPoPService:
    @staticmethod
    def _safe_base64_url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

    @staticmethod
    def calculate_jwk_thumbprint(jwk: dict) -> str:
        """
        Tính toán mã SHA-256 Thumbprint (jkt) của một JSON Web Key (JWK) theo chuẩn RFC 7638.
        Chỉ hỗ trợ thuật toán mã hóa Elliptic Curve (chuẩn khóa ES256) được khuyên dùng cho DPoP.
        """
        if jwk.get("kty") != "EC":
            raise HTTPException(status_code=400, detail="Chỉ hỗ trợ định dạng khóa EC (ES256) để tối ưu hiệu năng")
        
        # Sắp xếp các trường bắt buộc của khóa EC theo thứ tự bảng chữ cái để băm nhất quán
        required_fields = {
            "crv": jwk["crv"],
            "kty": jwk["kty"],
            "x": jwk["x"],
            "y": jwk["y"]
        }
        json_canonical = json.dumps(required_fields, separators=(',', ':'), sort_keys=True)
        sha256_hash = hashlib.sha256(json_canonical.encode('utf-8')).digest()
        return DPoPService._safe_base64_url_encode(sha256_hash)

    @staticmethod
    def verify_dpop_proof(request: Request, dpop_header: str, access_token_payload: dict) -> bool:
        """
        Thực thi xác minh 6 ranh giới bảo mật cốt lõi của chuỗi DPoP Proof
        """
        if not dpop_header:
            raise HTTPException(status_code=401, detail="Thiếu Header DPoP bắt buộc")

        try:
            # 1. Bóc tách phần Header của DPoP Proof lấy khóa JWK
            unverified_header = jwt.get_unverified_header(dpop_header)
            client_jwk = unverified_header.get("jwk")
            if not client_jwk:
                raise HTTPException(status_code=401, detail="DPoP Proof thiếu trường chứa Public Key (jwk)")
            
            # Chuyển đổi JWK sang Object Public Key
            public_key = jwt.algorithms.ECAlgorithm.from_jwk(client_jwk)

            # 2. Giải mã chữ ký số của DPoP Proof
            proof_payload = jwt.decode(
                dpop_header, 
                public_key, 
                algorithms=["ES256"], 
                options={"verify_signature": True}
            )
            
            # 3. KIỂM TRA BẤT BIẾN NGỮ CẢNH (htm, htu)
            current_method = request.method
            current_url = str(request.url).split('?')[0] # Chuẩn hóa URL, bỏ query string
            
            if proof_payload.get("htm") != current_method:
                raise HTTPException(status_code=401, detail="Mismatch HTTP Method trong DPoP Proof")
            if proof_payload.get("htu") != current_url:
                raise HTTPException(status_code=401, detail="Mismatch HTTP URI đích đến trong DPoP Proof")

            # 4. KIỂM TRA CỬA SỔ THỜI GIAN (iat)
            current_time = int(time.time())
            proof_iat = proof_payload.get("iat", 0)
            if abs(current_time - proof_iat) > 60:
                raise HTTPException(status_code=401, detail="DPoP Proof hết hạn hoặc lệch thời gian hệ thống quá 60 giây")

            # 5. CHỐNG TẤN CÔNG PHÁT LẠI (jti Replay Detection)
            proof_jti = proof_payload.get("jti")
            if not proof_jti:
                raise HTTPException(status_code=401, detail="DPoP Proof thiếu định danh jti chống lặp")
            if proof_jti in JTI_CACHE:
                raise HTTPException(status_code=403, detail="Phát hiện tấn công Replay! Proof này đã được sử dụng")
            
            JTI_CACHE.add(proof_jti) # Đánh dấu jti đã xử lý

            # 6. RÀNG BUỘC CHÉO VỚI ACCESS TOKEN (Binding Verification)
            cnf_claim = access_token_payload.get("cnf")
            if not cnf_claim or "jkt" not in cnf_claim:
                raise HTTPException(status_code=401, detail="Access Token không chứa định danh ràng buộc cnf.jkt")
            
            calculated_jkt = DPoPService.calculate_jwk_thumbprint(client_jwk)
            if calculated_jkt != cnf_claim["jkt"]:
                raise HTTPException(status_code=401, detail="CẢNH BÁO: Phát hiện giả mạo Token! Khóa thiết bị không khớp")

            return True

        except jwt.PyJWTError as e:
            raise HTTPException(status_code=401, detail=f"Cấu trúc DPoP Proof không hợp lệ: {str(e)}")
