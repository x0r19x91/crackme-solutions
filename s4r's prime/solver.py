#!/usr/bin/python

s = "113e5c6eac71358d3a4727639f55f02457565ae57662a2a2727610d84646".decode("hex")
s = map(ord, s)
k = "Th4t's a P455W0rD"
for i in xrange(len(s)):
    s[i] ^= ord(k[i%len(k)])

m = {}
for i in xrange(0x20, 0x7f):
    k = pow(0x81, i, 0xfb)
    if k not in m:
        m[k] = []
    m[k].append(chr(i))

ans = []
for i in s:
    ans.append(m[i][0])

print ''.join(ans)
