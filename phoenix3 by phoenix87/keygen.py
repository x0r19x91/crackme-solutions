import sys

def hash(name):
    ans = 0xdeadc0de
    for ch in map(ord, name):
        t = ch << 8 | ch
        t = t << 0x10 | t
        ans ^= t
        ans &= 0xfefed0d0
        ans |= 0x159a3
        ans = (ans>>16 ^ (ans & 0xffff)) & 0xffff
    return ans

def main(name):
    h = hash(name)
    f = [0, 1]
    for i in xrange(47):
        f.append(f[-1]+f[-2] & 0xffffffff)
    s = []
    for i in xrange(5):
        s.append((h ^ f[21+i]) & 0xffff)
    serial = '-'.join(map(lambda i: '%05d' % i, s))
    act = 'fcfdfefcfbfbfbf8f0f1f2f0fffffffcecedeeecfbfbfbf8'
    print "[ -=-=-=-=- KeyG3n -=-=-=-=- ]"
    print "User Name :", name
    print "Serial Key:", serial
    print "Activation Code:", act

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print "Usage: %s [username]" % sys.argv[0]
        exit(0)
    main(sys.argv[1])