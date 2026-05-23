package authz

import rego.v1

# 1. Khai báo luật mặc định (Luôn từ chối nếu không khớp luật nào)
default decision := {
    "allow": false,
    "reason": "Mặc định từ chối: Request không đáp ứng bất kỳ thuộc tính bảo mật nào."
}

# 2. Luật ABAC: Cấp quyền dựa trên Thuộc tính (Attributes)
decision := {
    "allow": true,
    "reason": sprintf("Chấp nhận: User '%v' có thuộc tính phòng ban [%v] khớp với tài nguyên.", [input.user.username, input.user.department])
} if {
    input.user.department == input.resource.department
    input.action == "read"
}

# 3. Luật rẽ nhánh: Đặc quyền Admin
decision := {
    "allow": true,
    "reason": "Chấp nhận: User có đặc quyền Admin toàn hệ thống."
} if {
    input.user.role == "admin"
}