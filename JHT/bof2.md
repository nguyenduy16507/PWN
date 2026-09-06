 📒 Mục Tiêu:
  - Phân tích và kiểm soát tiến trình tràn bộ đệm (Buffer Overflow trên Stack)
     + Cơ chế tràn : Nhận dữ liệu đầu vào vượt quá kích thước mảng đệm để ghi đè tuấn tự lên ác biến mục tiêu trong Stack
  - Sử dụng pwntools
  - Bài toán minh họa sử dụng pwntools và GDB+GEF

 1️⃣ Các phân đoạn:
  * Tương tác và điểu khiển tiến trình(Scripting với Pwntools)
     - Việc sử dụng pwntools nhằm mục đích:
         + Tự động hóa việc đóng gói byte chính xác: các giá trị ghi đè như `0xCAFEBABE`,`0xDEADBEEF`,`0x13371337` là các số nguyên hexa 64-bit, khi đưa vào trong bộ nhớ kiến trúc x86-64, tuân theo little-endian nên nếu ta nhập thủ công thì không thế gõ được các byte nhị phân này
         -> Sử dụng hàm `p64()` của pwntools tự động chuyển đổi số nguyên thành chuỗi 8-byte đúng chuẩn nhị phân
         + Đồng bộ và điều khiển luồng nhập/xuất
         + Chuyển giao quyền điều khiển để tương tác với Shell
     - `process('./bof2')`: Khởi chạy file thực thi mục tiêu bên dưới dạng 1 tiến trình cục bộ(local process) để chuẩn bị truyền/nhận dữ liệu
     - `p64(giá_trị_hexa)`: Chuyển đổi số nguyên 64-bit hệ thập lục phan thành chuỗi byte theo đúng định dạng little-endian
     - `input()`: Tạm dừng kịch bản Python trước khi gửi payload. Đóng vai trò tạo khoảng nghỉ để lấy PID của tiến trình và gắn debugger
     - `send(payload)`: Gửi trực tiếp chuỗi byte vào luồng nhập của tiến trình
     - `sendafter(dấu_hiệu,payload)`: lắng nghe đầu ra từ chương trình , đợi đến khi xuất hện kí tự chỉ định nới thực hiện dữ liệu nhằm tránh trôi/mất payload
       VD: `sendafter(b'>',payload)` : lắng nghe đầu ra từ chương trình, đợi đên khi xuất hiện dấu `>` thì thực hiện payload
     - `interactive()`: Trả lại quyền diều khiển luồng I/O lại cho termianl người dùng khi diều kiện rẽ nhánh thành công
     - <img width="134" height="130" alt="Screenshot 2026-09-06 090805" src="https://github.com/user-attachments/assets/23e5af2e-96e4-4cf7-9f4a-7cc38299f789" />
       + Tạo file python : `subl tên.py`  VD: `sulb slove.py`
       + Chạy file gõ lệnh `python3 Tên_file`  VD: `python3 slove.py`

     **Lưu ý** :
       - Các hàm như `process()` và `sendafter(b'>',payload)` giúp script Python tự khởi chạy file thực thi và lắng nghe tiến trình, dữ liệu khai thác chỉ được gửi đi đúng vào thời điểm chương trình mục tiêu in ra nhắc lệnh `>` và sẵn sàng đọc, ngăn chặn trôi dữ liệu hoặc gửi đi quá sớm khi chương trình chưa nạp xong
       - Sau khi payload ghi đè thành công và kích họa hàm `system("/bin/sh")`, lệnh `p.interactive()` đóng vai trò là cầu nối , nó bàn giao lại toàn bộ luồng vào/ra (stdin/stdout) lại cho terminal
      
  * Kiếm chứng động và đo đạc bộ nhớ (GDB + GEF)
     - `attach <PID>` sau khi vào trình `gdb`  hoặc `gdb -p <PID>`: Móc gắn trình gỡ lỗi GDB vào tiến trình `bof2` đang chạy dựa trên PID được in ra từ script python
        + Sau khi ta chạy `python3 tên_file` nó sẽ xuất ra 1 PID của tiến trình đó
        + Sử dụng lệnh `sudo gdb -p <PID>` nếu ko có quyền root
     -`vm`(hoặc`vmap`): Hiển thị bản đồ bộ nhớ ảo của tiến trình, dùng để giúp kiểm tra địa chỉ và quyền truy cập(`rwx`) của các phân vùng mã,`[stack]`,[heap], và các thư viện liên kết `libc`

