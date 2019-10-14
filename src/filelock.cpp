#include <iostream>
#include <fstream>
#include "aes.cpp"

#define BLOCK_SIZE 16

using namespace std;

void encrypt(fstream &file, const bool do_cbc, byte IV[16]);
void decrypt(fstream &file, const bool do_cbc, byte IV[16]);

void load_next_block(fstream &file, const int pos);
void write_block(fstream &file, const int pos);

// Globals
static union {
    byte block[BLOCK_SIZE];
    char block_str[BLOCK_SIZE];
};

int main(int argc, char* argv[]){

    if (argc != 5 && argc != 6) {

        cerr << "Please use (ECB mode): aes <-e/-d> <128/192/256> <key> <text>" << endl;
        cerr << "or" << endl;
        cerr << "Please use (CBC mode): aes <-e/-d> <128/192/256> <key> <IV> <text>" << endl;
        cerr << "Note, for decryption IV may be 0 or anything non-empty"<< endl;
        exit(1);
    }

    // Encrypt or decrypt flag
    const bool flag_e = argv[1][1] == 'e';

    // check CBC
    bool do_cbc = (argc == 6);
    byte IV[16];
    if (do_cbc && flag_e) stob(IV, argv[4], 16);

    // Get key and expand it.
    key_size = atoi(argv[2]);

    byte key[key_size/8];
    stob(key, argv[3], key_size/8);

    expand_key(expanded_key, key);

    // Get File
    const char* file_path = do_cbc ? argv[5] : argv[4];

    fstream file("test.txt",ios::in|ios::out|ios::out|ios::binary|ios::ate);

    if (!file.is_open()){
        cout << "Did not open." << endl;
        exit(1);
    }

    int file_size = file.tellg();
    file.seekg(0, ios::beg);

    // Process
    if (flag_e)
        encrypt(file, do_cbc, IV);

    else
        decrypt(file, do_cbc, IV);


    return 0;
}

void encrypt(fstream &file, const int file_size, const bool do_cbc, byte IV[16]){

    for (int pos=0; pos<file_size-16; pos+=16){
        load_next_block(file, pos);
        encrypt_block(block, BLOCK_SIZE, do_cbc, IV);
        write_block(file, pos);

        if (do_cbc) mov(IV, block, 16);
    } // append IV and padding info at end

}

void decrypt(fstream &file, const int file_size, const bool do_cbc, byte IV[16]){

    for (int pos=file_size-16; pos>=0; pos-=16){
        load_next_block(file, pos);
        encrypt_block(block, BLOCK_SIZE, do_cbc, IV);
        write_block(file, pos);
    } // does not update IV

}

void load_next_block(fstream &file, const int pos){
    file.seekg(pos, ios::beg);
    file.read(block_str, BLOCK_SIZE);
}

void write_block(fstream &file, const int pos){
    file.seekg(pos, ios::beg);
    file.write(block_str, BLOCK_SIZE);
}