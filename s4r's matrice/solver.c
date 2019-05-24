#include <stdio.h>
#include <stdint.h>

unsigned char w[] =
{
  0x0F, 0x06, 0x1F, 0x08, 0xA4, 0x16, 0x3C, 0x1A, 0x17, 0x1B, 
  0x98, 0x26, 0x18, 0x2D, 0x90, 0x30, 0x30, 0x2C, 0x7B, 0x25, 
  0xE7, 0x2C, 0x77, 0x34, 0xBB, 0x32, 0x6B, 0x2B, 0x14, 0x28, 
  0x4C, 0x2C, 0xE3, 0x2B, 0x37, 0x2A, 0x74, 0x27, 0x1C, 0x25, 
  0x29, 0x2C, 0xCF, 0x30, 0x1E, 0x2D, 0xEA, 0x15, 0xF6, 0x09, 
  0x8E, 0x12, 0x3C, 0x19, 0xE4, 0x1B, 0x2B, 0x2F, 0x5C, 0x17, 
  0x50, 0x07, 0x2C, 0x10, 0x5F, 0x2D, 0x01, 0x2B, 0xBA, 0x29, 
  0x58, 0x29, 0x0C, 0x33, 0x37, 0x16, 0xB6, 0x07, 0xE8, 0x05, 
  0xF0, 0x0C, 0x00, 0x00
};

int main() {
    uint16_t* p = (uint16_t*) w;
    char buf[100], *d = buf;
    *d++ = 47;
    uint16_t last = 33;
    while (*p) {
        *d++ = last;
        last = *++p/last;
    }
    *p = 0;
    printf("[*] Flag - %s\n", buf); /* /!?\I_hope_you_liked_win32_Dis4$sembly/*$\ */
}