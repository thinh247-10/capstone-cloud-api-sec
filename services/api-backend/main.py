from fastapi import FastAPI, HTTPException, Request, Header, Depends
from pydantic import BaseModel
import urllib.request
import json
from jose import jwt

# Các module nội bộ của dự án
from crypto_service import CryptoService
from dpop_service import DPoPService
from middleware import OPAMiddleware

# Khởi tạo ứng dụng FastAPI
app = FastAPI(
    title="SME API Service",
    description="Backend Microservices cho đồ án Cloud API Security",
    version="1.0.0"
)
crypto_service = CryptoService()

# ==============================================================================
# 1. ĐỊNH NGHĨA CẤU TRÚC DỮ LIỆU (SCHEMA) & MOCK DB
# ==============================================================================
class User(BaseModel):
    id: int
    username: str
    email: str
    role: str = "user"

class UserCreate(BaseModel):
    username: str
    cccd: str  # Số CCCD sẽ được mã hóa trước khi lưu vào DB

fake_users_db = [
    {"id": 1, "username": "thinh", "email": "thinh@example.com", "role": "admin"},
    {"id": 2, "username": "alice", "email": "alice@example.com", "role": "user"}
]

# ==============================================================================
# 2. CÁC ENDPOINT CƠ BẢN (CRUD & ENCRYPTION - TASK 2.1)
# ==============================================================================
@app.get("/")
def read_root():
    return {"message": "Hello from SME API Backend! Hạ tầng đã kết nối thành công."}

@app.get("/users/", response_model=list[User])
def get_users():
    """Lấy danh sách tất cả người dùng (Tạm thời chưa khóa Auth)"""
    return fake_users_db

@app.post("/api/users")
def create_user(user: UserCreate):
    """Endpoint tạo user mới - Thực hiện mã hóa CCCD trước khi 'lưu'"""
    encrypted_res = crypto_service.encrypt_data(user.cccd)

    new_user_entry = {
        "username": user.username,
        "cccd_ciphertext": encrypted_res["ciphertext"],
        "cccd_nonce": encrypted_res["nonce"]
    }
    
    return {
        "status": "Success",
        "saved_to_db": new_user_entry
    }

# ==============================================================================
# 3. XÁC THỰC TOKEN TỪ KEYCLOAK (TASK 2.2)
# ==============================================================================
KEYCLOAK_CERTS_URL = "http://localhost:8081/realms/master/protocol/openid-connect/certs"

def verify_keycloak_token(token: str):
    """Hàm gọi sang Keycloak tải Public Key và giải mã Token"""
    try:
        req = urllib.request.urlopen(KEYCLOAK_CERTS_URL)
        jwks = json.loads(req.read())

        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = key
                break
        
        if not rsa_key:
            raise HTTPException(status_code=401, detail="Không tìm thấy Public Key khớp với Token")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            options={"verify_aud": False} # Tạm tắt check Audience để dễ test
        )
        return payload

    except urllib.error.URLError:
        raise HTTPException(status_code=503, detail="Lỗi kết nối Keycloak (Cổng 8081 có đang mở không?)")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token đã hết hạn! Vui lòng đăng nhập lại.")
    except jwt.JWTClaimsError:
        raise HTTPException(status_code=401, detail="Sai thông tin Claims trong Token.")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token không hợp lệ: {str(e)}")

def get_access_token_payload(authorization: str = Header(None)):
    """Hàm Middleware trích xuất Token từ Request và gọi hàm giải mã"""
    if not authorization or not authorization.startswith("DPoP "):
        raise HTTPException(
            status_code=401, 
            detail="Yêu cầu định dạng 'Authorization: DPoP <Token>'"
        )
    
    try:
        actual_token = authorization.split(" ")[1]
        real_payload = verify_keycloak_token(actual_token)
        
        return {
            "username": real_payload.get("preferred_username", "unknown"),
            "role": "admin", 
            "department": "IT", 
            "cnf": real_payload.get("cnf", {}) # Mã vân tay DPoP từ Keycloak
        }
    except IndexError:
        raise HTTPException(status_code=401, detail="Định dạng Header DPoP sai.")

# ==============================================================================
# 4. BẢO VỆ ENDPOINT BẰNG NHIỀU LỚP (ZERO-TRUST)
# ==============================================================================
@app.get("/api/secure-data")
def get_secure_data(
    request: Request,
    dpop: str = Header(None), 
    token_payload: dict = Depends(get_access_token_payload)
):
    """Endpoint tuyệt mật: Xác thực Keycloak + Chống Replay DPoP + Phân quyền OPA"""
    
    # Lớp 1: Kiểm tra DPoP Proof (Chống Replay Attack)
    DPoPService.verify_dpop_proof(
        request=request, 
        dpop_header=dpop, 
        access_token_payload=token_payload
    )
    
    # Lớp 2: Kiểm tra OPA Authorization (Phân quyền ABAC)
    OPAMiddleware.verify_access(request, user_payload=token_payload, resource_department="IT")

    return {
        "status": "Success",
        "data": "Đây là dữ liệu mật cấp độ cao.",
        "security": "Được bảo vệ bởi IdP (Keycloak) + DPoP Zero-Trust + OPA"
    }

# Entry point để chạy server trực tiếp bằng lệnh `python main.py`
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)