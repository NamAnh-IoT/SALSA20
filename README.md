# SALSA20
[Liên kết đến slide](https://canva.link/87l794fgwm700ge)

Salsa20 hoạt động bằng cách sử dụng key, nonce (mã dùng 1 lần), counter, và constant (hằng số cố định của thuật toán) kết hợp lại trên mảng 4x4 sau đó thực hiện biến đổi 20 lần để tạo ra keystream

Cụ thể, ban đầu thuật toán sẽ tạo ra 1 ma trận 4x4
[C1] [K1] [K2] [K3]
[K4] [C2] [N1] [N2]
[c1] [c2] [C3] [K5]
[K6] [K7] [K8] [C4]

với C là Constant (hằng số mặc định của thuật toán)
    K là Key 32 bytes được tách thành 8 mảnh 32 bit
    N là Nonce 8 bytes được tách thành 2 mảnh 32 bit
    c là counter 8 bytes và tăng 1 sau mỗi lần chạy
Mỗi lần chạy Nonce cần được thay đổi và không được trùng lặp để tránh bị XOR 2 ciphertext làm triệt tiêu keystream
