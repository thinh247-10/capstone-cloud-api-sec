import time
import uuid
import requests
import jwt
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec

print("=========================================================")
print("🛡️ KÍCH HOẠT KỊCH BẢN PENTEST ZERO-TRUST DPOP")
print("=========================================================\n")

# 1. TẠO KHÓA THIẾT BỊ CỦA CLIENT (HACKER/USER)
print("🔑 1. Đang khởi tạo vân tay thiết bị (ES256 Key Pair)...")
client_private_key = ec.generate_private_key(ec.SECP256R1())
jwk_dict = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(client_private_key.public_key()))
# Tính JKT tự động
req_fields = {"crv": jwk_dict["crv"], "kty": jwk_dict["kty"], "x": jwk_dict["x"], "y": jwk_dict["y"]}
jkt = base64.urlsafe_b64encode(hashlib.sha256(json.dumps(req_fields, separators=(',', ':'), sort_keys=True).encode()).digest()).decode().rstrip('=')

print(f"👉 VÂN TAY THIẾT BỊ HIỆN TẠI (JKT) LÀ: {jkt}")
print("⚠️ LƯU Ý QUAN TRỌNG: Hãy copy đoạn mã JKT ở trên, mở file 'main.py' và thay thế vào vị trí 'cnf.jkt'.")
print("Sau khi lưu file main.py, hãy quay lại đây và nhấn ENTER để bắt đầu bắn phá API...")
input()

# Cấu hình API
API_URL = "http://localhost:8002/api/secure-data" # Đổi thành 8000 nếu em đang chạy cổng 8000
ACCESS_TOKEN = "DPoP dummy_token_from_keycloak"

def generate_dpop_proof(method, url):
    payload = {"jti": str(uuid.uuid4()), "htm": method, "htu": url, "iat": int(time.time())}
    headers = {"typ": "dpop+jwt", "jwk": jwk_dict}
    return jwt.encode(payload, client_private_key, algorithm="ES256", headers=headers)

# ==========================================
# THỰC THI 3 KỊCH BẢN PENTEST THEO YÊU CẦU
# ==========================================

print("\n🚀 BẮT ĐẦU PENTEST...\n")

# KỊCH BẢN 1: Chống đánh cắp Token (Thiếu DPoP)
print("[-] Test Case 1: Hacker lấy được Access Token nhưng không có DPoP Proof")
res1 = requests.get(API_URL, headers={"Authorization": ACCESS_TOKEN})
print(f"   -> Kết quả: {res1.status_code} - {res1.json().get('detail')}")
assert res1.status_code == 401, "Lỗi: API đã để lọt request không có DPoP!"

# KỊCH BẢN 2: Chống thao túng ngữ cảnh (Đổi Method/URL)
print("\n[-] Test Case 2: Hacker có Proof, nhưng mang đi gọi API khác (Sai URL)")
fake_proof = generate_dpop_proof("GET", "http://localhost:8002/api/hack-data")
res2 = requests.get(API_URL, headers={"Authorization": ACCESS_TOKEN, "DPoP": fake_proof})
print(f"   -> Kết quả: {res2.status_code} - {res2.json().get('detail')}")
assert res2.status_code == 401, "Lỗi: API không chặn sai lệch URL!"

# KỊCH BẢN 3: Chống phát lại (Replay Attack)
print("\n[-] Test Case 3: Hacker chặn bắt được request HỢP LỆ, và gửi lại lần 2 (Replay Attack)")
valid_proof = generate_dpop_proof("GET", API_URL)
# User hợp pháp gọi lần 1
res_valid = requests.get(API_URL, headers={"Authorization": ACCESS_TOKEN, "DPoP": valid_proof})
print(f"   -> Lần 1 (User thật gọi): {res_valid.status_code} - {res_valid.json().get('status')}")
# Hacker gửi y chang lần 2
res_replay = requests.get(API_URL, headers={"Authorization": ACCESS_TOKEN, "DPoP": valid_proof})
print(f"   -> Lần 2 (Hacker Replay): {res_replay.status_code} - {res_replay.json().get('detail')}")
assert res_replay.status_code == 403, "Lỗi: API không chặn Replay Attack!"

print("\n✅ TẤT CẢ TEST CASE ĐỀU PASS! HỆ THỐNG ĐÃ AN TOÀN TUYỆT ĐỐI THEO CHUẨN DPOP ZERO-TRUST!")