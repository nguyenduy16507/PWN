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
     
    
