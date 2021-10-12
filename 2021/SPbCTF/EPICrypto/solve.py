import struct

p16 = lambda x: struct.pack('<H',x)

with open('./flag.png.encrypted','rb') as f:
    enc = f.read()

dic = {}
origin = b''
with open('save.txt','r') as f:
    for i in range(0xffff+1):
        dic[int(f.readline().strip(),16)] = i

    for m in range(0,len(enc),2):
        origin += p16(dic[int.from_bytes(enc[m:m+2],byteorder='little')])

    with open('flag_decode.png','wb') as f:
        f.write(origin)

# spbctf{0k_l3ts_4ctu4LLy_3ncRyp7_y0_fl4g}