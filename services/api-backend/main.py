from fastapi import FastAPI, HTTPException, Request, Header, Depends
from pydantic import BaseModel
import urllib.request
import json
from jose import jwt
from sqlalchemy.orm import Session
from database import engine, get_db, Base
import models

# Các module nội bộ của dự án
from crypto_service import CryptoService
from dpop_service import DPoPService
from middleware import OPAMiddleware

# Tự động tạo bảng trong DB nếu chưa có
models.Base.metadata.create_all(bind=engine)

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
    cccd: str  # Dữ liệu nhạy cảm gửi lên (sẽ bị mã hóa)

# ĐÂY LÀ LỚP KHIÊN CHỐNG EXCESSIVE DATA EXPOSURE
class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

    class Config:
        from_attributes = True

# DTO cho Order
class OrderCreate(BaseModel):
    item_name: str
    price: int

class OrderResponse(BaseModel):
    id: int
    item_name: str
    price: int
    owner_username: str

    class Config:
        from_attributes = True

# ==============================================================================
# 2. CÁC ENDPOINT CƠ BẢN (CRUD & ENCRYPTION - TASK 2.1)
# ==============================================================================
@app.get("/")
def read_root():
    return {"message": "Hello from SME API Backend! Hạ tầng đã kết nối thành công."}

@app.get("/users/", response_model=list[UserResponse])
def get_users(db: Session = Depends(get_db)):
    """Lấy danh sách tất cả người dùng TỪ DATABASE THẬT"""
    users = db.query(models.UserDB).all()
    return users

@app.post("/api/users")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """Endpoint tạo user mới - Lưu trực tiếp xuống PostgreSQL"""
    
    # 1. Gọi service Vault để mã hóa CCCD
    encrypted_res = crypto_service.encrypt_data(user.cccd)

    # 2. Chuẩn bị dữ liệu Model để nhét vào DB
    new_db_user = models.UserDB(
        username=user.username,
        cccd_ciphertext=encrypted_res["ciphertext"],
        cccd_nonce=encrypted_res["nonce"]
    )
    
    # 3. Ra lệnh lưu xuống PostgreSQL
    db.add(new_db_user)
    db.commit()
    db.refresh(new_db_user) # Cập nhật lại để lấy được ID do DB cấp
    
    return {
        "status": "Success",
        "message": f"Đã lưu User {new_db_user.username} (ID: {new_db_user.id}) an toàn vào PostgreSQL",
        "data_saved": {
            "id": new_db_user.id,
            "username": new_db_user.username
        }
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
        "user_info": token_payload,  # <-- THÊM DÒNG NÀY ĐỂ CHUYỀN DATA ĐI TIẾP
        "security": "Được bảo vệ bởi IdP (Keycloak) + DPoP Zero-Trust + OPA"
    }
# ==============================================================================
# 3. MỞ RỘNG API NGHIỆP VỤ (ORDERS) - MỤC 7.1 & 10.2
# Yêu cầu: Tất cả API ở đây phải bọc middleware OPA & DPoP (get_secure_data)
# ==============================================================================

@app.post("/api/orders", response_model=OrderResponse)
def create_order(
    order: OrderCreate, 
    db: Session = Depends(get_db),
    # ĐÂY LÀ LỚP KHIÊN BẢO VỆ: Gọi hàm check Token & OPA trước khi chạy code
    security_context: dict = Depends(get_secure_data)
):
    """Tạo đơn hàng mới (Chỉ dành cho User đã xác thực & OPA cho phép)"""
    
    # Lấy thông tin user từ Token (do Keycloak cấp và middleware bóc tách ra)
    user_info = security_context.get("user_info", {})
    # SỬA DÒNG DƯỚI ĐÂY: đổi "preferred_username" thành "username"
    current_username = user_info.get("username", "anonymous")
    # Lưu xuống DB thật
    new_order = models.OrderDB(
        item_name=order.item_name,
        price=order.price,
        owner_username=current_username
    )
    db.add(new_order)
    db.commit()
    db.refresh(new_order)
    
    return new_order


@app.get("/api/orders", response_model=list[OrderResponse])
def get_all_orders(
    db: Session = Depends(get_db),
    # TIẾP TỤC BỌC KHIÊN BẢO VỆ
    security_context: dict = Depends(get_secure_data)
):
    """Lấy danh sách đơn hàng (OPA kiểm duyệt quyền Read)"""
    orders = db.query(models.OrderDB).all()
    return orders

# Entry point để chạy server trực tiếp bằng lệnh `python main.py`
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)