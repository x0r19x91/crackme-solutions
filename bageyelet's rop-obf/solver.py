#!/usr/bin/python

a = [0x83,0x36,0x9d,0xcd,0xec,0xf6]
b = [0x87,0x3e,0x92,0xdd,0xfb,0xdc]
for i in xrange(6):
    a[i] ^= b[i]

print ' '.join(str(i) for i in a)
