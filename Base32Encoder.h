/***************************************************************************************
*    Title: Base32 Encoding In C++
*    Author: MadeBits 2018
*    Project: cpp-base32
*    Date: 07.11.2018
*    Availability: https://github.com/madebits/cpp-base32
*
***************************************************************************************/

#ifndef BASE32ENCODER_H
#define BASE32ENCODER_H

#include <cstring>

struct Base32Encoder {
    static bool Encode32(const unsigned char* in, int inLen, unsigned char* out);

    static int  GetEncode32Length(int bytes);
};


#endif //BASE32ENCODER_H
