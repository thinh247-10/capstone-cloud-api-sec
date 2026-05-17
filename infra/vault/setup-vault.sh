#!/bin/bash

# --- DÒNG MA THUẬT QUYẾT ĐỊNH ---
# Tự động bắt tọa độ file script và ép Terminal di chuyển về thư mục "infra" (thư mục cha của vault)
cd "$(dirname "$0")/.." || exit
# -------------------------------

echo "🚀 BẮT ĐẦU KHỞI TẠO LẠI VAULT TỰ ĐỘNG..."

# Cài đặt công cụ đọc JSON (jq) nếu Ubuntu của sếp chưa có
sudo apt update -y && sudo apt install -y jq

# Khai báo biến đường tắt vào Vault
export VAULT_CMD="sudo docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root sme-vault vault"

echo "🔑 1. Khởi tạo Transit Engine cho Backend..."
$VAULT_CMD secrets enable transit || true
$VAULT_CMD write -f transit/keys/backend-db-enc

echo "🛡️ 2. Khởi tạo PKI Engine & Đúc Root CA..."
$VAULT_CMD secrets enable pki || true
$VAULT_CMD secrets tune -max-lease-ttl=87600h pki
$VAULT_CMD write -format=json pki/root/generate/internal common_name="SME Internal CA" ttl=87600h > root_ca.json

# Tự động trích xuất CA lưu vào file (Đường dẫn gốc từ infra)
jq -r '.data.issuing_ca' root_ca.json > certs/ca/root_ca.crt

echo "📝 3. Cấp quyền Role mTLS..."
$VAULT_CMD write pki/roles/sme-mtls-role allowed_domains="sme-backend,sme-kong,localhost" allow_bare_domains=true allow_subdomains=true allow_localhost=true max_ttl=720h

echo "🔐 4. Đúc chứng chỉ cho Kong Gateway..."
$VAULT_CMD write -format=json pki/issue/sme-mtls-role common_name="sme-kong" > kong.json
jq -r '.data.private_key' kong.json > certs/kong/kong.key
jq -r '.data.certificate' kong.json > certs/kong/kong_fullchain.crt
jq -r '.data.ca_chain[0]' kong.json >> certs/kong/kong_fullchain.crt

echo "🔐 5. Đúc chứng chỉ cho Backend API..."
$VAULT_CMD write -format=json pki/issue/sme-mtls-role common_name="sme-backend" > backend.json
jq -r '.data.private_key' backend.json > certs/backend/backend.key
jq -r '.data.certificate' backend.json > certs/backend/backend_fullchain.crt
jq -r '.data.ca_chain[0]' backend.json >> certs/backend/backend_fullchain.crt

# Dọn dẹp rác JSON tạm thời
rm root_ca.json kong.json backend.json

echo "✅ KHỞI TẠO THÀNH CÔNG! Đang nạp chứng chỉ mới vào hệ thống..."
# Dùng tên container trực tiếp để khởi động lại
sudo docker restart sme-gateway sme-backend

echo "🎉 XONG! HỆ THỐNG ĐÃ SẴN SÀNG!"