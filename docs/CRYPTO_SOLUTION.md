# II. Crypto Solution: Giải Pháp Mật Mã 3 Lớp

## 1. Lớp Crypto (Bảo vệ dữ liệu & Quản trị khóa)

- **Truyền tải (In-transit):** Thiết lập **TLS 1.3** làm tiêu chuẩn duy nhất trên toàn hệ thống. Áp dụng Ciphersuites AEAD thu gọn (`TLS_AES_256_GCM_SHA384`) và **tắt hoàn toàn tính năng 0-RTT** để chặn đứng Replay Attack.
- **Lưu trữ (At-rest):** Triển khai **Envelope Encryption** trước khi ghi xuống Database. Ứng dụng Backend dùng thuật toán `AES-256-GCM` để mã hóa PII. Vault cấp phát khóa DEK dùng một lần cho mỗi bản ghi, thiết lập cơ chế quản trị Nonce chặt chẽ ở cấp độ hệ thống, triệt tiêu lỗi Nonce Reuse.
- **Chữ ký điện tử:** Thay thế RSA bằng hệ mật **Ed25519** tại Keycloak để ký JWT, tối ưu hiệu năng xác thực tại Gateway.
- **Quản trị khóa (KMS):** HashiCorp Vault quản lý toàn bộ vòng đời khóa (Versioning, Auto-Rotate SLA $\le 10$ phút, Revoke khẩn cấp).

## 2. Lớp AuthN (Xác thực Định danh)

- **Người dùng (Client):** Triển khai luồng **WebAuthn/FIDO2** làm phương thức chống Phishing cốt lõi. TOTP là phương án fallback không cho phép bypass. Gateway/IdP thực thi Rate-limit và Lockout tài khoản ($\le 1s$) để chống Brute-force.
- **Dịch vụ (Service-to-Service):** 100% giao tiếp East-West trong mạng VPC bắt buộc chạy qua **mTLS**. Vault hoạt động như Root CA nội bộ, cấp phát và xoay vòng chứng thư số (X.509) tự động cho các containers.
- **Quản lý Phiên:** Token được cấu hình vòng đời cực ngắn (TTL 5-15 phút) nhằm thu hẹp bán kính sát thương (Blast-radius).

## 3. Lớp AuthZ (Kiểm soát Ủy quyền)

- **Kiến trúc Thi hành (Enforcement):** Chuyển đổi mô hình phân quyền sang **ABAC** (Attribute-Based Access Control) với triết lý Zero-Trust (**Deny-by-default**). Kong Gateway đóng vai trò PEP, đẩy kiểm tra phân quyền về OPA (vai trò PDP).
- **Minh bạch (Explainability):** Mọi quyết định Allow/Deny từ OPA Rego bắt buộc phải xuất ra `log reason` phục vụ kiểm toán bảo mật.
- **Bảo mật Token (Token Hardening):** \* Cổng Gateway chặn đứng các token cấu hình `alg=none` hoặc lỗi `kid` injection.
  - Tích hợp **DPoP (Demonstrating Proof-of-Possession)**: Trói buộc JWT với định danh thiết bị của Client, vô hiệu hóa hoàn toàn các token bị đánh cắp mang sang thiết bị khác sử dụng.
