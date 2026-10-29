- `process & remote`: kết nối tới 1 tiến trình cục bộ(local process) hoặc 1 máy chủ từ xa(remote server)
- `send & recv` : Truyền(gửi) và nhận dữ liệu
- `interactive` : Giao tiếp trực tiếp với tiến trình đang kết nối thông qua giao diện dòng lệnh(terminal)
- `context.log_level` : Thiết lập mức độ chi tiết của dữ liệu được in ra màn hình, chẳng hạn như các gói dữ liệu đã gửi và nhận
- `packing & unpacking` : Chuyển đổi số nguyên thành mảng byte(đóng gói) hoặc từ mảng byte ngược lại thành số nguyên(mở gói)
- `gdb.attach` : Gỡ lỗi(debug) một tiến trình cục bộ bằng trình gỡ lỗi GDB
- `asm & disasm` : Biên dịch(assemble) mã hợp ngữ (assembly) thành mã máy(machine code) hoặc dịch ngược (disassemble) mã máy trở lại thành mã hợp ngữ
- `ELF` : Thu thập và phân tích các thông tin liên quan đến tệp tin thực thi định dạng ELF 

1. Quản lý kểt nối & tiến trình
   -
- `process()`
  + cú pháp `p = process('./ten_file_thuc_thi')`
    VD : `p =process('./r2s')`
  + Mục đích : Khởi chạy 1 tệp nhị phân có sẵn trên máy tính như 1 tiến trình con, mở đường ống để Python có thể đọc/ghi dữ liệu với tiến trình đó
  + Ta sử dụng nó trong giai đoạn phát triển script, gỡ lỗi(kết hợp với GDB), kiểm tra độ chính xác của payload bằng cách offset trước khi mang đi tấn công server thật
- `remote()`
  + cú pháp : `p = remote('HOST', PORT)`
  VD : `p = remote('host3.dreamhack.games', 14160)`
  + Mục đích : Khởi tạo 1 kết nối mạng TCP với máy chủ mục tiêu đang chạy chương trình bị lỗi
  + Sử dụng khi script khai thác đã hoàn thiện, cần bắn payload thẳng vào server của giải đấu CTF/wargame để lấy cờ thực tế
- `interactive()`
   + Cú pháp : `p.interactive()`
   + Mục đích : Trả lại luồng I/O (bàn phím và màn hình) của tiến tình về cho người dùng thao tác trực tiếp
   + Luôn đặt ở dòng cuối cùng của 1 script khai thác , khi payload  đã bẻ lái thành công và tạo 1 shell (`/bin/sh`) , lệnh này sẽ cho phép ta gõ cá lệnh như 1 terminal bình thường : `cat flag` , `ls`,..
     
2. Nhận dữ liệu từ mục tiêu
   -
- `recvuntil()`
  + cú pháp : `p.recvuntil(b'chuoi_nhận_diện')` hoặc `p.recvuntil(b'chuoi_nhận_diện', drop=True)`
  VD `p.recvuntil(b'+', drop=True)` : nhận và đọc dữ liệu cho đến khi thấy dấu `+` thì dừng lại, khi ấy trong chuỗi nhận và đọc được có cả dấu + ở đó nên `drop=True` có chức năng xóa dấu `+` đi và dữ lại chuỗi đã nhận và đọc được 
 + Ta dùng nó để đồng bộ hóa luồng dữ liệu. Thường thì chương trình sẽ rất dài và nhiều câu hỏi rườm rà nên việc dùng lệnh này để bắt script chờ đến dúng khoảng khắc xuất hiện chuỗi mình mong muốn rồi mưới đọc dữ liệu thật hoặc bơm payload (Vd  chờ chữ như `Input:` hoặc `buf:`)
- `recvline()`
   + Cú pháp : `data = p.recvline()[:-1]`
   + Mục đích : đọc trọn vẹn 1 dòng văn bản cho đến khi gặp ký tự xuống dòng (`\n`). Việc thêm vào đó `[:-1]` ở cuối là thao tác cắt bỏ byte `\n` dư thừa đó đi
   + Ta sử dụng nó khi chương trình chủ động in ra địa chỉ bộ nhớ theo từng dòng
   + VD: với câu lệnh sau `printf("%p\n", buf)` , ta lấy đc nguyên dòng địa chỉ đó rồi ép kiểu sang hex để dùng
- `recvn()`
  + Cú pháp : `data = p.recvn(Số)`
    VD `data = p.recvn(7)`
  + Mục đích : Bắt buộc đọc chính xác số lượng byte được chỉ định, ko cần quan tâm nó là văn bản hay byte NULL, rác.
  + Bắt buộc phải sử dụng byte này khi ta hứng Canary hoặc địa chỉ của bộ nhớ bị rò rỉ, vì Canary chứa các byte thô(ko thể in thành chữ), nếu dùng `recvline()` nó có thể bị ngắt sai chỗ , còn dùng `recvn()` thì nó sẽ ép python lấy đúng số byte mà đc chỉ định ra
    
3. Bơm Payload tấn công(Send)
   -
-`sendafter()`
   + Cú pháp : `p.sendafter(b'dấu_hiệu', payload)`
   + Mục đích : là sự kết hợp giữa `recvuntil()` và `send()`. nó đợi chương trình in ra `'dấu_hiệu'` sau đó lập tức đẩy `payload` vào mà ko cần chèn thêm dấu xuống dòng (`\n`)
   + Sử dụng khi ta tấn công qua lỗ hổng của hàm `read()`. hàm `read()` chỉ đếm số lượng byte chứ ko cần dấu entern để kếp thúc việc nhập
- `sendlineafter()`
  + cú pháp: `sendlineafter(b'dấu_hiệu', payload)`
  + Mục đích : Như bên trên nhưng ở đây khác biệt là nó sẽ tự động chèn byte xuống dòng (`\n`) vào cuối payload(như là ta thao tác xong gõ enter)
  + Sử dụng khi tấn công các hàm đọc cuỗi như `gets()`, `scanf()`, `fgets()`, vì cá hàm này đều quy định dấu hiệu kết thúc luồng nhập là phím enter
    
4.  Định dạng bộ nhớ
    - `p64()`(Pack 64-bit)
       + Cú pháp :`p64(Chuỗi_dia_chi)`
         VD : `p64(0x7ffe5087ec30)` sẽ sinh ra luồn byte sau: `b'0\xec\x87P\xfe\x7f\x00\x00'`
       + Mục đích : Ép 1 số nguyên toán học thành 1 chuỗi 8 byte theo tuân chuẩn little-endian
       + Ta sử dụng nó trong khâu lắp ráp payload. CPU kiến trúc x86-64 đọc bộ nhớ ngược nên khi ta muốn ghi đè canary  hoặc nhét địa chỉ của `buf` đè lên thanh ghi RET thì bắt buộc phải bọc con số đó qua `p64()` để mã hóa ngược nó lại.
    - `u64()`(Unpack 64-bit)
       + Cú pháp: `u64(b'\x00' + recvn(7))`
       + Mục đích: ngược lại với `p64()`, nó lấy 8 byte thô theo định dạn little-edian giải mã trở lại thành 1 số nguyên bình thường
       + Sử dụng khi ta lấy được 7byte Canary bằng `recvn(7)`, ghép thêm byte `\x00` vào đầu để đủ 8byte, để in log ra dễ nhìn hay +,- tính toán offsets
5. Mã khai thác (Assembly)
   -
- `asm()` : để lấy đoạn shellcode nạp vào đầu payload
- bắt buộc phải khai báo `context.arch = 'amd64'` ở đầu script để pwntools biết cần dịch theo kiểu kiến trúc CPU nào
  
**Lưu ý**    
- Trạng thái của dữ liệu :
  + Trạng thái 1 : Chuỗi văn bản (String/hex string): Để hiển thị ra màn hình cho người đọc, máy tính ko dùng cái này để tính toán hay chạy lệnh được
    VD : `0x4005d6`
  + Trạng thái 2 : Số nguyên : Dành cho python làm toán (cộng, trừ khoảng cách offset)
    VD: `4195798`
  + Trạng thái 3 : Byte thô(Raw Bytes) : Dành cho CPU và bộ nhớ hiểu
    VD: `b'\xd6\x05\x40\x00\x00\x00\x00\x00'`
- Công cụ chuyển đổi: 
  + `int(chuỗi, 16)` : Từ mắt người (String) -> python(integer)
  + `hex(số_nguyen)`: từ python(integer) -> mắt người(string)
  + `p64(số_nguyen)`(pack 64-bit): từ pyhton(integer) -> CPU (raw bytes)
  + `u64(chuỗi_raw_bytes)`(unpack 64-bit) : Từ CPU(raw bytes) ->python(integer) 
