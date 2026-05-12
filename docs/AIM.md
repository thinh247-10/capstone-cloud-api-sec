# I. Asset-centric & Risk analysis (AIM)

## 1. Ngữ cảnh & Ràng buộc (Context & Constraints)

- **Chủ đề:** Ứng dụng mật mã học bảo vệ API và dữ liệu cho kiến trúc SME Cloud (Microservices).
- **Ràng buộc SME:** Thuê hạ tầng Cloud (không kiểm soát vật lý phần cứng), đội ngũ vận hành mỏng (nguy cơ hardcode khóa).
- **Trust Boundary:** Internet (Vùng không tin cậy) -> Kong API Gateway (Ranh giới) -> Mạng nội bộ VPC chứa Services, IdP, Vault, DB (Vùng tin cậy).

## 2. Danh mục tài sản cốt lõi (Asset Inventory)

- **A1 - Dữ liệu (Data):** Thông tin định danh (PII) và Dữ liệu nghiệp vụ. Tồn tại ở 3 trạng thái: _At-rest_ (trong DB), _In-transit_ (qua mạng), _In-process_ (trên RAM). Độ nhạy: Cao đến Rất cao.
- **A2 - Bí mật & Khóa (Secrets & Keys):** Khóa ký JWT (Ed25519), Khóa mã hóa dữ liệu (Vault KEK/DEK), Database credentials. Độ nhạy: Tuyệt mật.
- **A3 - Danh tính (Identity):** Định danh Client (End-user) và định danh Service (Container).
- **A4 - Trạng thái & Chính sách (Policies):** Trạng thái phiên (JWT Claims: `sub`, `role`, `exp`), Chính sách phân quyền (OPA Rego - ABAC/RBAC).
- **A5 - Hạ tầng tin cậy (Trusted Infra):** Kong Gateway (PEP), Keycloak (IdP), HashiCorp Vault (KMS/CA).

## 3. Phân tích rủi ro & Mục tiêu bảo vệ (SMART)

| Rủi ro chính                   | Giải pháp Mật mã tầng thấp                                 | Mục tiêu SMART                                              |
| :----------------------------- | :--------------------------------------------------------- | :---------------------------------------------------------- |
| **Nghe lén & Replay Attack**   | Bắt buộc TLS 1.3 (tắt 0-RTT); Ràng buộc token bằng DPoP.   | **0 byte** plaintext rò rỉ; Tỷ lệ Replay thành công **0%**. |
| **BOLA & Leo thang đặc quyền** | Mô hình Deny-by-default; Kiểm tra quyền bằng OPA (ABAC).   | Policy pass-rate **$\ge 95\%$**; Deny 100% kèm log lý do.   |
| **Lộ Database Snapshot**       | Envelope Encryption (AES-256-GCM + Vault DEK) tại Backend. | Lỗi trùng lặp Nonce (Nonce reuse) = **0**.                  |
| **Lộ khóa mã hóa (Key Leak)**  | Quản trị vòng đời khóa tự động bằng HashiCorp Vault.       | Rotate khóa **$\le 10$ phút**; Blast-radius **$\le 24h$**.  |

## 4. Các Invariants (Khẳng định bất biến)

- **I1:** Không rò rỉ plaintext trên mọi kênh truyền tải.
- **I2:** Tampering (chỉnh sửa ciphertext/token trái phép) bị từ chối 100% và ghi log.
- **I3:** Tính toàn vẹn của dữ liệu gốc được bảo đảm.
- **I4:** AuthN chống Phishing; Token bắt buộc có ràng buộc sở hữu (DPoP) chống Replay.
- **I5:** Mọi quyết định AuthZ đều **giải thích được** thông qua Audit Log.
- **I6:** Vận hành khóa **quan sát được**: Xoay vòng nhanh, giới hạn bán kính sát thương.
