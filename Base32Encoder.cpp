/***************************************************************************************
*    Title: Base32 Encoding In C++
*    Author: MadeBits 2018
*    Project: cpp-base32
*    Date: 07.11.2018
*    Availability: https://github.com/madebits/cpp-base32
*
***************************************************************************************/

#include "Base32Encoder.h"

int Base32Encoder::GetEncode32Length(int bytes) {
    int bits = bytes * 8;
    int length = bits / 5;
    if((bits % 5) > 0) {
        length++;
    }
    return length;
}


static bool Encode32Block(unsigned const char* in5, unsigned char* out8) {
    // pack 5 bytes
    unsigned long long int buffer = 0;
    for(int i = 0; i < 5; i++) {
        if(i != 0) {
            buffer = (buffer << 8);
        }
        buffer = buffer | in5[i];
    }
    // output 8 bytes
    for(int j = 7; j >= 0; j--) {
        buffer = buffer << (24 + (7 - j) * 5);
        buffer = buffer >> (24 + (7 - j) * 5);
        unsigned char c = (unsigned char)(buffer >> (j * 5));
        // self check
        if(c >= 32) return false;
        out8[7 - j] = c;
    }
    return true;
}

bool Base32Encoder::Encode32(const unsigned char* in, int inLen, unsigned char* out) {
    if((in == 0) || (inLen <= 0) || (out == 0)) return false;

    int d = inLen / 5;
    int r = inLen % 5;

    unsigned char outBuff[8];

    for(int j = 0; j < d; j++) {
        if(!Encode32Block(&in[j * 5], &outBuff[0])) return false;
        memmove(&out[j * 8], &outBuff[0], sizeof(unsigned char) * 8);
    }

    unsigned char padd[5];
    memset(padd, 0, sizeof(unsigned char) * 5);
    for(int i = 0; i < r; i++) {
        padd[i] = in[inLen - r + i];
    }
    if(!Encode32Block(&padd[0], &outBuff[0])) return false;
    memmove(&out[d * 8], &outBuff[0], sizeof(unsigned char) * GetEncode32Length(r));

    return true;
}