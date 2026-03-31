# Salsa20 

Dự án này hiện thực hóa thuật toán mã hóa dòng **Salsa20** bằng ngôn ngữ C. Ngoài việc kiểm tra tính đúng đắn của thuật toán, project còn bao gồm một ứng dụng thực tế để mã hóa và giải mã dữ liệu điểm ảnh của các file hình ảnh định dạng BMP.

[Liên kết đến slide thuyết trình](https://canva.link/87l794fgwm700ge)


## 📖 Nguyên lý hoạt động

Salsa20 hoạt động bằng cách sử dụng Key, Nonce (mã dùng 1 lần), Counter (bộ đếm), và Constant (hằng số cố định) kết hợp lại trên một mảng trạng thái $4 \times 4$. Sau đó, thuật toán thực hiện biến đổi hàm băm (hàm nén) 20 lần để tạo ra một chuỗi **keystream** ngẫu nhiên. Chuỗi này sẽ được XOR với plaintext để tạo ra ciphertext.

### Ma trận trạng thái ban đầu (State Matrix)

Ban đầu thuật toán sẽ khởi tạo một ma trận $4 \times 4$ chứa các từ 32-bit (words) như sau:

| Cột 0 | Cột 1 | Cột 2 | Cột 3 |
| :---: | :---: | :---: | :---: |
| **C1** | **K1** | **K2** | **K3** |
| **K4** | **C2** | **N1** | **N2** |
| **c1** | **c2** | **C3** | **K5** |
| **K6** | **K7** | **K8** | **C4** |

**Trong đó:**
* **C (Constant):** Hằng số mặc định của thuật toán (thường là chuỗi "expand 32-byte k").
* **K (Key):** Khóa bí mật 32 bytes được chia thành 8 mảnh 32-bit.
* **N (Nonce):** Mã số dùng một lần 8 bytes được chia thành 2 mảnh 32-bit.
* **c (Counter):** Bộ đếm 8 bytes, tự động tăng lên 1 sau mỗi block dữ liệu 64-byte được tạo ra.

> ⚠️ **Lưu ý quan trọng:** Mỗi lần thực hiện mã hóa một thông điệp mới, Nonce cần được thay đổi và không được trùng lặp. Việc lặp lại Nonce sẽ dẫn đến lỗ hổng bảo mật nghiêm trọng do các keystream bị trùng lặp và triệt tiêu lẫn nhau khi bị XOR.

---

## 📁 Cấu trúc thư mục

* `salsa20.c` & `salsa20.h`: Mã nguồn thư viện và định nghĩa hàm xử lý thuật toán Salsa20.
* `test_salsa20.c`: Mã nguồn dùng để chạy test kiểm tra thuật toán.
* `img_converter.c`: Mã nguồn ứng dụng đọc file ảnh BMP, thực hiện mã hóa/giải mã và xuất file ảnh.
* `input.bmp`: Ảnh gốc đầu vào dùng để thử nghiệm.
* `output.bmp`: Ảnh sau khi đã được mã hóa (toàn bộ pixel bị xáo trộn thành nhiễu).
* `decrypted.bmp`: Ảnh sau khi giải mã ngược từ `output.bmp` (khớp hoàn toàn với ảnh gốc).

---

## 🚀 Hướng dẫn sử dụng

### 1. Yêu cầu hệ thống
* Trình biên dịch C (như GCC, Clang hoặc MSVC).
* Hệ điều hành hỗ trợ CLI (Linux, macOS, Windows).

### 2. Biên dịch và Chạy Test
Để kiểm tra tính đúng đắn của thuật toán Salsa20 với các test vector:

**Trên Linux/macOS:**
```bash
gcc salsa20.c test_salsa20.c -o test_salsa20
./test_salsa20
```

**Trên Windows (GCC/MinGW):**
```bash
gcc salsa20.c test_salsa20.c -o test_salsa20.exe
.\test_salsa20.exe
```

### 3. Mã hóa file ảnh BMP
Để chạy thử nghiệm mã hóa file ảnh trực quan:

```bash
# Biên dịch chương trình chuyển đổi ảnh
gcc salsa20.c img_converter.c -o img_converter

# Chạy chương trình (đảm bảo file input.bmp đã nằm cùng thư mục)
./img_converter
```
* Chương trình sẽ đọc dữ liệu từ `input.bmp`, tiến hành mã hóa và lưu thành `output.bmp`.
* Sau đó, nó sẽ tự động dùng lại Key và Nonce đó giải mã ngược `output.bmp` thành `decrypted.bmp`. Bạn có thể mở các file ảnh lên để so sánh kết quả trực quan!
1. Bạn hãy copy toàn bộ nội dung trong khung đen ở trên.
2. Mở file `README.md` trên repository của bạn (hoặc tạo mới nếu chưa có).
3. Dán đè toàn bộ nội dung cũ và lưu lại là bạn đã có một giao diện giới thiệu cực kỳ chuyên nghiệp rồi!
