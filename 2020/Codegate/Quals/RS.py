def enc(v4, v5):
    v3 = 0
    while (v5):
        if (v5 & 1) == 1:
            v3 ^= v4
        v4 *= 2
        if (v4 >= 256):
            v4 ^= 285
        v5 >>= 1
    return v3

def get(a1):
    for i in range(256):
        if enc(static[-1],i) == ord(a1[31]):
            c = i
            break
    res = chr(c)
    for i in range(0, 32):
        k = enc(static[i], c)
        res += chr(ord(a1[i]) ^ k)
    return res

data = 'ef434b3f5eb9f0d08cb57e6f7bc8a67b09e2619d98035f565d66820b9e2b76925bc3dcf23cd0b6816034a566cabd7d6a00fee40b44e1ba81cbae8b240ba51f6dba0e611a30a777512341a61ac07f71719fd593e538ce528b2586b312b7a71c43b4088147aed61846c56b69630bcc95ab49536fdebe2f2ed99bdcdd7669a4f058'.decode('hex')
static = [0x74,0x40,0x34,0xae,0x36,0x7e,0x10,0xc2,0xa2,0x21,0x21,0x9d,0xb0,0xc5,0xe1,0x0c,0x3b,0x37,0xfd,0xe4,0x94,0x2f,0xb3,0xb9,0x18,0x8a,0xfd,0x14,0x8e,0x37,0xac, 0x58]
flag = ''
for i in range(0,len(data),32):
    slc = data[i:i+32]
    for i in range(16):
        slc = get(slc)
    flag += slc
print flag.replace('\x00','')
