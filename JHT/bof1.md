📒 `Muc Tiêu` : 
- Giới thiệu cơ bản về Buffer Overflow trên Stack
   + `Cơ chế lưu trên Stack` : Bộ nhớ Stack lưu trữ dữ liệu từ trên xuống dưới theo chiều địa chỉ tăng dần(Từ địa chỉ thấp đến địa chỉ cao)
   + `Hiện tượng tràn bộ đệm(Buffer Overflow)`: Khi một biến mảng đệm nhận dữ liệu đầu vòa nhiều hơn sức chứa mà chương trình không kiểm tra kích thước giới hạn, phần dữ liệu dư thừa sẽ tràn xuống dưới và ghi đè trực tiếp lên giá trị của các biến nằm liền sau nó.

- Bài toán minh họa sử dụng các kĩ thuật cơ bản để khai thác và chiếm `shell`

1️⃣ `Các phân đoạn` : 
- Dịch ngược và phân tích lỗ hổng(Decompile với `IDA Pro/Ghidra`)
   + Nhìn vào  `main` ta có thể nhận biết thấy biến mảng ban đầu chỉ được cấp phát 16 byte trong khi đó hàm `read` bên dưới lại cho phép nhập tới `0x30 ~ 48 byte`
   + Điều kiện để ta chiến được `shell` là khi làm cho 3 biến phía dưới có giá trị khác 0, thì chương trình sẽ mở `shell` hệ thống
   + Ta có thể tính toán được : 16 byte đầu lấp đầy mảng + 8 byte(ghi đè) + 8 byte(ghi đè) + 8 byte(ghi đè) = 40 byte (<48 byte của hàm read -> thỏa mãn)
     -> Ta cần nhập vào 40 byte là sẽ thành công mở shell
  - Thực thi khai thác(Exploit) :
     + Ta dùng python để tạo chuỗi 40 chứ A `'A' * 40`
     + chạy chương trình và dán chuỗi A trên vào sau dấu nhắc `>`
     + Chương trình sẽ in ra giá trị của 3 biến và ta thấy nó khác 0 , thỏa mãn điều kiện để mở thành công shell `bin/sh`


  **Lưu ý**: Kiểm chứng động và đo đạc bộ nhớ (GDB+GEF)
  - Để xem trực tiếp ô nhớ tương ứng thì ta dùng lệnh `x/gx + ...`
  - Lệnh `pattern create 0x30` để tạo chuỗi mẫu không lặp có độ dài 48 byte
  - Lệnh `pattern search <địa chỉ>` để GEF tự động tính toán chính xác số byte cần nhập trước khi bắt đầu ghi đè vào từng biến
     + VD : trước khi ghi đè vào v5 ta phải lấp đầy khoảng chống 16 byte của hàm `buf` thì khi ta dùng lệnh `pattern search + địa_chỉ_của_v5` nó sẽ tự đo đạc số byte cần nhập vào trước khi bắt đầu ghi đè vào v5 là 16 byte.
   - Mở python để tạo chuỗi bằng lệnh `python 3` 
