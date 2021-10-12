# Keyword : UPX, PE Structure, EXE Reversing

# Step1
# UPX PE Bianry
# 40740 Bytes -> PE Real Size == 41472 Bytes
# with open('garbage.exe','ab') as f:
# 	f.write(b'\x00'*(41472-40740))

# Setp2
'''
$ upx.exe -d garbage.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2017
UPX 3.94w       Markus Oberhumer, Laszlo Molnar & John Reiser   May 12th 2017

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     79360 <-     41472   52.26%    win32/pe     garbage.exe

Unpacked 1 file.
'''

# Step3
# Using CFF Explorer
# 1. PE Resoruce XML Remove
# 2. Import DLL Name Repair (Kernel32.dll, shell32.dll)
# 3. execute .EXE

# flag : Congrats! Your key is: C0rruptGarbag3@flare-on.com

# Solution 2
# Static Analysis

import struct


p = lambda x: struct.pack('<L',x)

v11 = 'KglPFOsQDxBPXmclOpmsdLDEPMRWbMDzwhDGOyqAkVMRvnBeIkpZIhFznwVylfjrkqprBPAdPuaiVoVugQAlyOQQtxBNsTdPZgDHs'
v14 = p(0x3B020E38) + p(0x341B3B19) + p(0x3E230C1B) + p(0x42110833) + p(0x731E1239)

# sink_the_tanker.vbs
print(''.join(str(chr((v14[i]^(ord(v11[i%(len(v14))]))))) for i in range(20)))

v10 = 'nPTnaGLkIqdcQwvieFQKGcTGOTbfMjDNmvibfBDdFBhoPaBbtfQuuGWYomtqTFqvBSKdUMmciqKSGZaosWCSoZlcIlyQpOwkcAgw'
v12 = p(0x2C332323) + p(0x49643F0E) + p(0x40A1E0A) + p(0x1A021623) + p(0x24086644)
v12 += p(0x2C741132) + p(0xF422D2A) + p(0xD64503E) + p(0x171B045D) + p(0x5033616)
v12 += p(0x8092034) + p(0xE242163) + p(0x58341415) + p(0x3A79291A) + p(0x58560000)
v12 += b'\x84'

# MsgBox("Congrats! Your key is: C0rruptGarbag3@flare-on.com")
print(''.join(str(chr((v12[i]^(ord(v10[i%(len(v12))]))))) for i in range(60)))