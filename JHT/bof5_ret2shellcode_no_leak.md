I.Mindset khai thác 
- Kỹ thuật ret2shellcode yêu cầu bạn phải biết chính xác địa chỉ của Stack để bẻ lái luồng thực thi(RIP) nhảy vào đó. Nhưng có những trường hợp chương trình bật ASRL(địa chỉ stack sẽ thanh đổi ngẫu nhiên), ta cần phải thêm 1 bước chính là rò rỉ bộ nhớ(`leak`)
- Còn ở phần ret2shellcode không leak này chính là 1 biến thể, nó không cần rò rỉ địa chỉ(leakress) nhờ có các yếu tố sau:
  + Lỗ hổng buffer overflow cho phép ghi đè ngập stack từ vùng biến cục bộ xuống tận `saved RIP`(địa chỉ trả về của hàm)
  + Theo quy ước gọi hàm thì giá trị trả về của các hàm nhập chuỗi (như là `read` hay `get`) là con trỏ tới chính chuỗi đó và được tự lưu vào trong thanh ghi `RAX`. Chương trình sẽ không dọn dẹp biến này, Rax lúc này sẽ như là 1 hướng dẫn trỏ thẳng vào shellcode
  + ROP gadge (call rax): thay vì ghi đè `saved RIP` bằng địa chỉ stack ngẫu nhiên, ta sẽ ghi đè nó bằng địa chỉ tĩnh của lệnh `call rax`, rồi từ đó nó nhảy tới thanh ghi rax , xem địa chỉ mà thanh ghi này đang giữ là gì và nhảy thẳng đến đó để thực thi.
- Với challenge này, ta phân tích:
  + Hàm main hoàn toàn bình thường nên ktra sang hàm run
  + 
II.Phân tích tĩnh và động  
