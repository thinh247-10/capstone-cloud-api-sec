import time
import uuid
import json
import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec

print("=========================================================")
print("🛡️ KIỂM THỬ TÍCH HỢP: KEYCLOAK + DPOP + BACKEND")
print("=========================================================\n")

# 1. TẠO KHÓA THIẾT BỊ DPOP (Client Keypair)
print("🔑 1. Đang tạo khóa vân tay thiết bị (ES256)...")
private_key = ec.generate_private_key(ec.SECP256R1())
jwk_dict = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))

def generate_dpop_proof(url, method):
    """Hàm tự động sinh DPoP Proof cho mỗi request"""
    payload = {
        "jti": str(uuid.uuid4()),
        "htm": method,
        "htu": url,
        "iat": int(time.time())
    }
    headers = {"typ": "dpop+jwt", "jwk": jwk_dict}
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)

# 2. XIN TOKEN TỪ KEYCLOAK
KEYCLOAK_TOKEN_URL = "http://localhost:8081/realms/master/protocol/openid-connect/token"
USERNAME = "admin"  # User admin em vừa tạo trên giao diện web Keycloak
PASSWORD = "admin"  # Pass admin tương ứng

print(f"🌐 2. Đang đăng nhập Keycloak (User: {USERNAME}) và xin Token...")
# Sinh DPoP Proof dành riêng cho URL xin Token
dpop_proof_for_token = generate_dpop_proof(KEYCLOAK_TOKEN_URL, "POST")

res_kc = requests.post(
    KEYCLOAK_TOKEN_URL,
    data={
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": USERNAME,
        "password": PASSWORD
    },
    headers={
        "DPoP": dpop_proof_for_token  # Đính kèm vân tay để Keycloak trói vào Token
    }
)

if res_kc.status_code != 200:
    print("❌ Đăng nhập Keycloak thất bại:", res_kc.text)
    exit()

access_token = res_kc.json()["access_token"]
print("✅ Lấy Access Token thành công! (Token đã được gắn chặt với vân tay DPoP)")

# 3. GỌI BACKEND API ĐỂ KIỂM TRA XÁC THỰC
BACKEND_API_URL = "http://localhost:8002/api/secure-data"

print("\n🚀 3. Đang gọi Backend API để lấy dữ liệu bảo mật...")
# Sinh DPoP Proof mới dành riêng cho URL của Backend
dpop_proof_for_api = generate_dpop_proof(BACKEND_API_URL, "GET")

res_api = requests.get(
    BACKEND_API_URL,
    headers={
        "Authorization": f"DPoP {access_token}",
        "DPoP": dpop_proof_for_api
    }
)

print(f"-> HTTP Status trả về: {res_api.status_code}")
if res_api.status_code == 200:
    print("🎉 XUẤT SẮC! DATA TRẢ VỀ TỪ BACKEND:")
    print(json.dumps(res_api.json(), indent=2, ensure_ascii=False))
else:
    print("❌ LỖI XÁC THỰC TỪ BACKEND:", res_api.json())