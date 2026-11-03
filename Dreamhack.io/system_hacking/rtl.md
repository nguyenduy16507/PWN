* C
```sh
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```
* Analysis 
- kiểm tra các cơ chế bảo vệ `pwn checksec ./rtl`:
 + <img width="430" height="75" alt="image" src="https://github.com/user-attachments/assets/a997afeb-2e23-495c-a5c4-46d240d67974" />
 + `NX enabled` là ko thể thực thi sellcode trên stack
 + `Canary found` có chim hoàng yến canh gác địa chỉ trả về
- Nhìn vào mã nguồn C ta thấy : 
 + ` char buf[0x30];` : Biến `buf` chỉ đc cấp phát 0x30 byte
 + `read(0, buf, 0x100);` : Hàm `read` lại cho phép nhập tới 256byte 
-> Ta có thể thấy đc đây là 1 lỗi buffer overflow , cho phép chúng ta ghi đè ngoài vùng nhớ của hàm `buf` 
- Nhưng vì NX đang bật nên chúng ta ko thể bơm shellcode vào stack đc mà phải sử dụng các hàm có sẵn trong tiến trình `system@plt`
 + `const char* binsh = "/bin/sh";` và  `ystem("echo 'system@plt'");`
- GD1: Vì có canary bảo vệ địa chỉ trả về nên trước tiên ta cần leak canary ra trước bằng cách nhập dữ liệu vừa đủ để ghi đè lên byte `\x00` đầu tiên của Canary, hàm `printf`sẽ in ra và làm rò rỉ 7 byte Canary còn lại 
- GD2: Ta nhập lại Canary vào đúng vị trí để có thể vượt qua kiểm tra, sau đó ghi đè địa chỉ trả về bằng 1 chuỗi ROP để thiết lập đối số và gọi `system("/bin/sh")` 
- GD3: Để gọi được `system("/bin/sh")` trên kiến trúc x86-64 thì quy ước gọi hàm yêu cầu đối số thứ nhất phải nằm trong thanh ghi `rdi` nên ta cần chuẩn bị : 
  + Địa chỉ của `system@plt`: có thể lấy được dễ dành qua cú pháp `e.plt['system']` của pwntools hoặc sử dụng `info func @plt` trong GDB để lấy đc địa chỉ chính xác của `system@plt`
    
    <img width="212" height="92" alt="image" src="https://github.com/user-attachments/assets/9a7faa7a-b7c1-479f-813a-d81f319760c1" />

  + Chuỗi "/bin/sh" nằm sẵn trong file binary, ta lấy qua `next(e.share(b"/bin/sh"))` hoặc sử dụng lệnh `grep /bin/sh` hay `search-pattern "/bin/sh"` 
  + Tìm ROP gadgets `pop rdi; ret` : một đoạn mã dùng để bốc giá trị trên cùng của của stack bỏ vào `rdi` : `ROPgasdget --binary ./rtl --re "pop rdi"` trong terminal 
  + gadget `ret` : dùng để căn chỉnh ngăn xếp 
- Khoảng các từ `buf` đến `return address` của hàm real được tính như sau :
  + Ta đặt breakpoint tại địa chỉ của hàm `read` đầu tiên, khi hàm read được thực thi thì ta nhập thử 1 chuỗi 8 byte rác vào sẽ thấy nó đẩy ngay hàm buf, ta thấy được địa chỉ của hàm buf
  + khi dùng lệnh `info frame` để tìm địa chỉ của return address thì thấy `rip at 0x7fffffffdc98` đây chính là địa chỉ của return address
  + Ta thực hiện lệnh tính toán khoảng cách `p 0x7fffffffdc98 - 0x00007fffffffdc50` để tính ra khoảng cách giữa hàm buf và return address là `0x48` byte
  + <img width="458" height="297" alt="image" src="https://github.com/user-attachments/assets/f8f038b6-e607-4075-a9f1-36387ea08813" />
- ```sh
    Địa chỉ cao (High Address)
   |----------------------|
   |    Return Address    | (8 byte)  <-- Đích đến ta cần ghi đè
   |----------------------|
   |      Saved RBP       | (8 byte)  
   |----------------------|
   |       Canary         | (8 byte)  <-- Chốt chặn cần bảo toàn
   |----------------------|
   |       Padding        | (8 byte)  <-- đây là khoảng cách = khoảng cách(giữa buf và return address) - 0x30 byte(buf)
   |----------------------|
   |      buf[0x30]       | (48 byte) <-- Nơi ta bắt đầu nhập dữ liệu
   |----------------------|
    Địa chỉ thấp (Low Address)
  ```
* exploit
- khi ấy ra có cấu trúc stack payload như sau:  
  + 
  
