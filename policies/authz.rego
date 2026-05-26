package authz

import rego.v1

# ƯU TIÊN 1: Nếu là Admin -> Cho phép luôn và dừng lại, không xét tiếp luật sau
decision := {
    "allow": true,
    "reason": "Chấp nhận: User có đặc quyền Admin toàn hệ thống."
} if {
    input.user.role == "admin"
}

# ƯU TIÊN 2: Nếu không phải Admin nhưng cùng phòng ban -> Cho phép đọc dữ liệu
else := {
    "allow": true,
    "reason": sprintf("Chấp nhận: User '%v' có thuộc tính phòng ban [%v] khớp với tài nguyên.", [input.user.username, input.user.department])
} if {
    input.user.department == input.resource.department
    input.action == "read"
}

# MẶC ĐỊNH: Nếu không thỏa mãn bất kỳ điều kiện nào ở trên -> Từ chối truy cập
else := {
    "allow": false,
    "reason": "Mặc định từ chối: Request không đáp ứng bất kỳ thuộc tính bảo mật nào."
}