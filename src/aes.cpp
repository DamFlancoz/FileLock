#include <iostream>

#include "aes.h"

#define byte uint8_t
#define BLOCK_SIZE 16

namespace aes{

    // Globals
    int key_size;
    byte expanded_key[256]; // makes space assuming 256-bit key

    extern void encrypt_block(byte block[BLOCK_SIZE], const bool &do_cbc, const byte IV[16]){

        byte Rounds = key_size/32 + 7;  // no. of round

        if (do_cbc) eor(block, IV, 16);

        // key whitening
        add_key(expanded_key, block, true); // Also reset rounds to 0

        for(int round=1; round<Rounds-1; round++){

            sub_bytes(block);
            shift_rows(block);
            mix_cols(block);
            add_key(expanded_key, block);
        }
        // Last Round
        sub_bytes(block);
        shift_rows(block);
        add_key(expanded_key, block);
    }

    extern void decrypt_block(byte block[BLOCK_SIZE], const bool &do_cbc, const byte IV[16]){

        byte Rounds = key_size/32 + 7;  // no. of round

        // First decryption round
        inv_add_key(expanded_key, block, true); // Also reset rounds for this block
        inv_shift_rows(block);
        inv_sub_bytes(block);

        for(int round=1; round<Rounds-1; round++){

            inv_add_key(expanded_key, block);
            inv_mix_cols(block);
            inv_shift_rows(block);
            inv_sub_bytes(block);
        }

        // decrypt key whitening
        inv_add_key(expanded_key, block);

        if (do_cbc) eor(block, IV, 16);
    }

    // AES Layers

    extern void sub_bytes(byte block[], const int &len){

        static const byte sbox[] = {0x63,0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f,
            0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca,
            0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2,
            0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36,
            0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31,
            0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
            0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c,
            0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1,
            0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0,
            0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02,
            0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92,
            0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3,
            0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4,
            0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f,
            0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
            0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24,
            0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7,
            0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c,
            0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b,
            0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61,
            0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98,
            0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce,
            0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
            0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

        for(int i=0; i<len; i++){
            block[i]=sbox[block[i]];
        }
    }

    extern void shift_rows(byte block[BLOCK_SIZE]){
        /*
        Here, consecutive bytes are stacked as columns instead of rows,

        i.e. 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 -->

        1  5  9  13
        2  6  10 14
        3  7  11 15
        4  8  12 16
        */
        byte temp[16]={ block[0],block[5],block[10],block[15],
                        block[4],block[9],block[14],block[3],
                        block[8],block[13],block[2],block[7],
                        block[12],block[1],block[6],block[11]};

        for(int i=0; i<16; i++){
            block[i]=temp[i];
        }
    }

    extern void mix_cols(byte block[BLOCK_SIZE]){
        byte temp[4];
        for(int c=0; c<16; c+=4 ){

            /* multiple column vector c, [block[c],block[c+1],block[c+2],ac[+3]] by
            [2 3 1 1]
            [1 2 3 1]
            [1 1 2 3]
            [3 1 1 2]
            */
            temp[0] = gf2_mul(block[c],2) ^ gf2_mul(block[c+1],3) ^ gf2_mul(block[c+2],1) ^ gf2_mul(block[c+3],1);
            temp[1] = gf2_mul(block[c],1) ^ gf2_mul(block[c+1],2) ^ gf2_mul(block[c+2],3) ^ gf2_mul(block[c+3],1);
            temp[2] = gf2_mul(block[c],1) ^ gf2_mul(block[c+1],1) ^ gf2_mul(block[c+2],2) ^ gf2_mul(block[c+3],3);
            temp[3] = gf2_mul(block[c],3) ^ gf2_mul(block[c+1],1) ^ gf2_mul(block[c+2],1) ^ gf2_mul(block[c+3],2);

            // copy from temp
            block[c]=temp[0]; block[c+1]=temp[1]; block[c+2]=temp[2]; block[c+3]=temp[3];
        }
    }

    extern void add_key(byte expanded_key[], byte block[BLOCK_SIZE], const bool &reset){
        static byte round;
        if (reset) round = 0;
        eor(block, &expanded_key[16*round],16);
        round++;
    }

    extern void inv_sub_bytes(byte block[], const int &len){

        static const byte inv_sbox[] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5,
            0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3,
            0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4,
            0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
            0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1,
            0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b,
            0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4,
            0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
            0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d,
            0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4,
            0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca,
            0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf,
            0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad,
            0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47,
            0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e,
            0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79,
            0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd,
            0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27,
            0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
            0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b,
            0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
            0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1,
            0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

        for(int i=0; i<len; i++){
            block[i]=inv_sbox[block[i]];
        }
    }

    extern void inv_shift_rows(byte block[BLOCK_SIZE]){
        // see shift rows
        byte temp[16]={ block[0],block[13],block[10],block[7],
                        block[4],block[1],block[14],block[11],
                        block[8],block[5],block[2],block[15],
                        block[12],block[9],block[6],block[3]};

        for(int i=0; i<16; i++){
            block[i]=temp[i];
        }
    }

    extern void inv_mix_cols(byte block[BLOCK_SIZE]){
        byte temp[4];
        for(int c=0; c<16; c+=4 ){

            /* multiple column vector c, [block[c],block[c+1],block[c+2],ac[+3]]
            */
            temp[0] = gf2_mul(block[c],0xe) ^ gf2_mul(block[c+1],0xb) ^ gf2_mul(block[c+2],0xd) ^ gf2_mul(block[c+3],0x9);
            temp[1] = gf2_mul(block[c],0x9) ^ gf2_mul(block[c+1],0xe) ^ gf2_mul(block[c+2],0xb) ^ gf2_mul(block[c+3],0xd);
            temp[2] = gf2_mul(block[c],0xd) ^ gf2_mul(block[c+1],0x9) ^ gf2_mul(block[c+2],0xe) ^ gf2_mul(block[c+3],0xb);
            temp[3] = gf2_mul(block[c],0xb) ^ gf2_mul(block[c+1],0xd) ^ gf2_mul(block[c+2],0x9) ^ gf2_mul(block[c+3],0xe);

            // copy from temp
            block[c]=temp[0]; block[c+1]=temp[1]; block[c+2]=temp[2]; block[c+3]=temp[3];
        }
    }

    extern void inv_add_key(byte expanded_key[], byte block[BLOCK_SIZE], const bool &reset){
        static byte round;
        if (reset) round = key_size/32+6;
        eor(block, &expanded_key[16*round],16);
        round--;
    }


    // Helper

    // GF(2^8) algebra
    extern byte gf2_mul(const byte &a, const byte &b){
        // Multiplies terms of GF(2^8)

        // Irreducible polynomial for AES, x^8+ x^4 + x^3 + x + 1
        static const uint16_t IRR = 0b100011011; // 0x11b

        uint16_t A = a; // to handle more than 8-bit intermediate values
        byte B = b;

        byte ans = 0;

        // until b is 0
        while(B){

            // add if bit-0 of b is 1
            if (B & 1) ans ^= A;

            // shift to account for place value of bits in b
            A <<= 1;

            // reduce if block goes outside the field
            if (A & 0x100) A ^= IRR;

            // shift to get next bit to bit 0
            B >>= 1;
        }

        return ans;
    }

    // For expand_key
    extern uint32_t g(const uint32_t &x){

        // round constant
        static byte rc = 1;

        // convert to byte array
        byte *b = (byte*) &x;

        // rotate 4-byte word
        byte temp[4] = {b[1],b[2],b[3],b[0]};

        // Use S-box
        sub_bytes(temp, 4);

        // XOR rc
        temp[0] = temp[0] ^ rc;

        // get next rc
        rc = (byte)(2*rc ^ (rc < 0x80 ? 0 : 0x1b));

        // converts byte array to uint_32_t keeping elements in place
        return *( (uint32_t*) temp );
    }

    extern void expand_key(byte expanded_key[], const byte key[BLOCK_SIZE]){

        bool key256 = (key_size == 256);
        byte N = key_size / 32; // length of key in 4-byte words
        byte R = N+7;  // no. of round keys needed
        byte key_rounds = R*4/N;
        uint32_t* W = (uint32_t*) expanded_key;

        // copy the key, round 0
        for(byte i=0; i<N; i++){
            W[i] = *(uint32_t*) (&key[4*i]);
        }

        for(byte round=1; round<key_rounds+1; round++){
            // denotes start/0 position for the round
            byte i = round*N;

            W[i] = W[i-N] ^ g(W[i-1]);

            for (byte j=1; j<N; j++){
                if (key256 && (i+j)%4==0){
                    W[i+j] = W[i+j-1];
                    sub_bytes( (byte*) &W[i+j] , 4);
                    W[i+j] ^= W[i+j-N];

                } else {
                    W[i+j] = W[i+j-N] ^ W[i+j-1];
                }
            }

        }
    }

    extern void stob(byte target[],const char src[],const int &len){
        for (int i=0; i<len; i++){

            char temp[2] = {src[2*i], src[2*i+1]};

            if (temp[0] == '\0' || temp[1] == '\0') break;

            target[i] = std::stoi(temp, nullptr, 16);
        }
    }

    extern void mov(byte target[], const byte src[], const int &elements){
        for (int i=0; i<elements; i++){
            target[i] = src[i];
        }
    }

    extern void eor(byte target[], const byte src[], const int &elements){
        for (int i=0; i<elements; i++){
            target[i] ^= src[i];
        }
    }


    // Debugging use

    extern void print_bytes(const byte block[], const int &len){
        for(int i=0; i<len; i++){
            std::cout << std::hex << (block[i]<16 ? "0" : "") << (int)(block[i]);
            if ((i+1)%4 == 0 && i!=1) std::cout << ' ';
        }
        std::cout << std::dec << std::endl;
    }

}
