import requests
from fastapi import Request, HTTPException, status

# Địa chỉ nội bộ của OPA trong mạng Docker
# Sửa đoạn cuối từ /allow thành /decision
OPA_URL = "http://localhost:8181/v1/data/authz/decision"


class OPAMiddleware:
    @staticmethod
    def verify_access(request: Request, user_payload: dict, resource_department: str = "IT"):
        """
        Hàm đóng gói thông tin (User, Resource, Action) và gửi sang OPA xin phán quyết.
        """
        # 1. Trích xuất Action dựa trên HTTP Method (GET -> read, POST -> write, v.v.)
        action_map = {"GET": "read", "POST": "write", "PUT": "update", "DELETE": "delete"}
        action = action_map.get(request.method, "read")

        # 2. Đóng gói dữ liệu gửi cho OPA chuẩn theo cấu trúc .rego
        opa_input = {
            "input": {
                "user": {
                    "username": user_payload.get("username", "unknown"),
                    "role": user_payload.get("role", "user"),
                    # Giả định user lấy từ token có trường department
                    "department": user_payload.get("department", "unknown") 
                },
                "resource": {
                    "department": resource_department
                },
                "action": action
            }
        }

        # 3. Bắn HTTP POST sang OPA Server
        try:
            response = requests.post(OPA_URL, json=opa_input, timeout=3)
            response.raise_for_status()
            
            opa_result = response.json().get("result", {})
            is_allowed = opa_result.get("allow", False)
            reason = opa_result.get("reason", "OPA không trả về lý do cụ thể.")

            # 4. Phán quyết: Nếu OPA say "No", văng lỗi 403 ngay lập tức
            if not is_allowed:
                print(f"[AUTHZ DENIED] User: {user_payload.get('username')} - Reason: {reason}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, 
                    detail=f"OPA Từ chối truy cập: {reason}"
                )
            
            # Nếu OPA say "Yes", cho phép đi tiếp
            print(f"[AUTHZ APPROVED] User: {user_payload.get('username')} - Reason: {reason}")
            return True

        except requests.exceptions.RequestException as e:
            # Lỗi kết nối đến OPA Server
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail=f"Lỗi hệ thống: Không thể kết nối tới máy chủ OPA ({str(e)})"
            )