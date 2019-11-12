#ifndef _AES_H_
#define _AES_H_

#define byte uint8_t
#define BLOCK_SIZE 16

namespace aes {

    extern int key_size;
    extern byte expanded_key[256]; // makes space assuming 256-bit key

    void encrypt_block(byte block[BLOCK_SIZE], const bool &do_cbc=false, const byte IV[BLOCK_SIZE]=nullptr);
    void decrypt_block(byte block[BLOCK_SIZE], const bool &do_cbc=false, const byte IV[BLOCK_SIZE]=nullptr);

    // AES Layers
    void sub_bytes(byte[], const int &len=BLOCK_SIZE);
    void shift_rows(byte[BLOCK_SIZE]);
    void mix_cols(byte[BLOCK_SIZE]);
    void add_key(byte[], byte[BLOCK_SIZE], const bool &reset=false);

    void inv_sub_bytes(byte[], const int &len=BLOCK_SIZE);
    void inv_shift_rows(byte[BLOCK_SIZE]);
    void inv_mix_cols(byte[BLOCK_SIZE]);
    void inv_add_key(byte[], byte[BLOCK_SIZE], const bool &reset=false);

    // Helper
    byte gf2_mul(const byte&, const byte&);
    uint32_t g(const uint32_t&);
    void expand_key(byte expanded_key[], const byte key[BLOCK_SIZE]); // Key schedule
    void stob(byte[], const char[], const int &len=BLOCK_SIZE);
    void mov(byte target[], const byte src[], const int &elements=BLOCK_SIZE);
    void eor(byte target[], const byte src[], const int &elements=BLOCK_SIZE);

    // Debuging use
    void print_bytes(const byte[], const int &len=BLOCK_SIZE);

}

#endif // AES_H