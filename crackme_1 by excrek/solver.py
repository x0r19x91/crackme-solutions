#!/usr/bin/python

def encode(name):
    a = []
    j = 1
    for i in name:
        if ord(i) <= 0x5f:
            a.append(chr(ord(i)+8+j))
        else:
            a.append(chr(ord(i)-8-j))
        j += 1
    return "".join(a)

def decode(s):
    return ''.join(chr(ord(s[i])+9+i) for i in xrange(len(s)))

def main(name):
    c1 = encode(name)
    c2 = sum(map(ord, decode('JejbWYRbSS[')))*(ord(name[4])-0x3a)
    c3 = decode(">hc;") + "-" + str(c2+sum(map(ord, c1)))
    print "[*] Code1 - %s" % c1
    print "[*] Code2 - %s" % c2
    print "[*] Code3 - %s" % c3
