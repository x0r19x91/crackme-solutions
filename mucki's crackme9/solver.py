import struct
import sys

def crc32(buf):
    ans = 0xffffffff
    for b in buf:
        ans ^= ord(b)
        for i in xrange(8):
            if ans & 1:
                ans = (ans >> 1) ^ 0xEDB88320
            else:
                ans >>= 1
    return ~ans & 0xffffffff

def solve(name):
    h = ~crc32(name) & 0xffffffff
    serial = struct.pack("<I", h).encode("base64").strip()
    # valid is at offset 0x12 from 004072A7
    return serial + "="*(18-len(serial))

def main():
    if len(sys.argv) == 1:
        print "Usage: %s [name]" % sys.argv[0]
        exit()
    print "[*] Serial:", solve(sys.argv[1])

if __name__ == '__main__':
    main()
