#include <cstdint>

#define byte uint8_t


void encrypt_block(byte plain_text[], int plain_text_size, bool do_cbc=false, byte IV[16]=nullptr);
void decrypt_block(byte cipher_text[], int cipher_text_size, bool do_cbc=false, byte IV[16]=nullptr);

// AES Layers
void sub_bytes(byte[], int len=16);
void shift_rows(byte[16]);
void mix_cols(byte[16]);
void add_key(byte[], byte[], bool reset=false);

void inv_sub_bytes(byte[], int len=16);
void inv_shift_rows(byte[16]);
void inv_mix_cols(byte[16]);
void inv_add_key(byte[], byte[], bool reset=false);

// Helper
byte gf2_mul(byte,byte);
uint32_t g(const uint32_t&);
void expand_key(byte expanded_key[],byte key[]); // Key schedule
void stob(byte[], char[], int len);
void mov(byte target[], byte src[], int elements);
void eor(byte target[], byte src[], int elements);

// Debuging use
void print_bytes(const byte[], int, bool raw=false);

// Globals
int key_size;
byte expanded_key[256]; // makes space assuming 256-bit key