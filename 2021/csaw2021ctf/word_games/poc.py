# -- coding: utf-8 --
from pwn import *

# ENV
PORT = 5001
HOST = "pwn.chal.csaw.io"
e = context.binary = ELF('./word_games')
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



r.sendlineafter('', payload)


r.interactive()
