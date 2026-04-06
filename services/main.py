from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Khởi tạo ứng dụng FastAPI (Nó sẽ tự tạo Swagger UI cho bạn!)
app = FastAPI(
    title="SME API Service",
    description="Backend Microservices cho đồ án Cloud API Security",
    version="1.0.0"
)

# 1. Định nghĩa cấu trúc dữ liệu (Schema)
class User(BaseModel):
    id: int
    username: str
    email: str
    role: str = "user"

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

# 3. Khung sườn chờ ghép Keycloak (Cho nhiệm vụ tiếp theo)
def verify_keycloak_token(token: str):
    # TODO: Mai chúng ta sẽ lấy Public Key từ http://localhost:8081
    # và giải mã JWT token tại đây.
    pass