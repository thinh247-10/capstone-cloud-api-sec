from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from crypto_service import CryptoService
from fastapi import Request, Header, Depends
from dpop_service import DPoPService

# Khởi tạo ứng dụng FastAPI (Nó sẽ tự tạo Swagger UI cho bạn!)
app = FastAPI(
    title="SME API Service",
    description="Backend Microservices cho đồ án Cloud API Security",
    version="1.0.0"
)
crypto_service = CryptoService()

# 1. Định nghĩa cấu trúc dữ liệu (Schema)
class User(BaseModel):
    id: int
    username: str
    email: str
    role: str = "user"

class UserCreate(BaseModel):
    username: str
    cccd: str  # Số CCCD sẽ được mã hóa trước khi lưu vào DB

# Dữ liệu giả lập (Mock Database) để test
fake_users_db = [
    {"id": 1, "username": "thinh", "email": "thinh@example.com", "role": "admin"},
    {"id": 2, "username": "alice", "email": "alice@example.com", "role": "user"}
]

# 2. Các Endpoint cơ bản
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
    # 1. Gọi service để mã hóa dữ liệu nhạy cảm
    encrypted_res = crypto_service.encrypt_data(user.cccd)

    # 2. Giả lập lưu vào DB (Dữ liệu lưu xuống là Ciphertext và Nonce)
    new_user_entry = {
        "username": user.username,
        "cccd_ciphertext": encrypted_res["ciphertext"],
        "cccd_nonce": encrypted_res["nonce"]
    }
    
    # Trả về kết quả để kiểm tra xem mã hóa có chạy không
    return {
        "status": "Success",
        "saved_to_db": new_user_entry
    }
# 3. Khung sườn chờ ghép Keycloak (Cho nhiệm vụ tiếp theo)
def verify_keycloak_token(token: str):
    # TODO: Mai chúng ta sẽ lấy Public Key từ http://localhost:8081
    # và giải mã JWT token tại đây.
    pass

# --- BỔ SUNG LOGIC DPOP CHO TASK 2.3 ---

def get_access_token_payload(authorization: str = Header(None)):
    """Hàm giả lập bóc tách Token (Sẽ thay bằng Keycloak sau)"""
    if not authorization or not authorization.startswith("DPoP "):
        raise HTTPException(
            status_code=401, 
            detail="Yêu cầu định dạng 'Authorization: DPoP <Token>'"
        )
    # Giả lập payload JWT do Keycloak trả về (đã chứa sẵn vân tay cnf.jkt)
    return {
        "sub": "user_id_12345",
        "username": "admin",
        "cnf": {
            "jkt": "K5INefoVLDFYjeQndfRMopwsVOfRtuz2sXPkVhdrAWg" # Vân tay thiết bị hợp lệ
        }
    }

@app.get("/api/secure-data")
def get_secure_data(
    request: Request,
    dpop: str = Header(None), 
    token_payload: dict = Depends(get_access_token_payload)
):
    """Endpoint tuyệt mật, ép buộc phải có DPoP Proof mới được vào"""
    
    # Kích hoạt bộ quét bảo mật DPoP
    DPoPService.verify_dpop_proof(
        request=request, 
        dpop_header=dpop, 
        access_token_payload=token_payload
    )
    
    return {
        "status": "Success",
        "data": "Đây là dữ liệu mật cấp độ cao.",
        "security": "Được bảo vệ bởi DPoP Zero-Trust"
    }