#include <iostream>
#include <fstream>
#include "aes.cpp"

#define BLOCK_SIZE 16

using namespace std;

void encrypt(fstream &file, const int file_size, const bool do_cbc, byte IV[16]);
void decrypt(fstream &file, const int file_size, const bool do_cbc, byte IV[16]);

void load_block(fstream &file, char block_str[], const int pos, const int size);
void write_block(fstream &file, char block_str[], const int pos, const int size);

// Globals

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
    const bool do_cbc = (argc == 6);
    byte IV[BLOCK_SIZE];
    if (do_cbc) stob(IV, argv[4], 16);

    // Get key and expand it.
    key_size = atoi(argv[2]);

    byte key[key_size/8];
    stob(key, argv[3], key_size/8);

    expand_key(expanded_key, key);
        print_bytes(key,key_size/8,0);

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
        encrypt(file, file_size, do_cbc, IV);
    else
        decrypt(file, file_size, do_cbc, IV);


    return 0;
}

void encrypt(fstream &file, const int file_size, const bool do_cbc, byte IV[BLOCK_SIZE]){
    union {
        byte block[BLOCK_SIZE];
        char block_str[BLOCK_SIZE];
    };

    byte _IV[BLOCK_SIZE];
    if (do_cbc) mov(_IV, IV, BLOCK_SIZE);

    for (int pos=0; pos<=file_size-BLOCK_SIZE; pos+=BLOCK_SIZE){
        load_block(file, block_str, pos, BLOCK_SIZE);
        print_bytes(block,BLOCK_SIZE,0);
        encrypt_block(block, BLOCK_SIZE, do_cbc, _IV);
        write_block(file, block_str, pos, BLOCK_SIZE);

        print_bytes(block,BLOCK_SIZE,0);

        if (do_cbc) mov(_IV, block, BLOCK_SIZE);
    } // append IV and padding info at end

    cout << endl;

}

void decrypt(fstream &file, const int file_size, const bool do_cbc, byte IV[BLOCK_SIZE]){
    union {
        byte block[BLOCK_SIZE];
        char block_str[BLOCK_SIZE];
    };

    union
    {
        byte _IV[BLOCK_SIZE];
        char _IV_str[BLOCK_SIZE];
    };

    for (int pos=file_size-BLOCK_SIZE; pos>=0; pos-=BLOCK_SIZE){
        if (pos == 0){
            mov(_IV, IV, BLOCK_SIZE);
        } else {
            load_block(file, _IV_str, pos-BLOCK_SIZE, BLOCK_SIZE);
        }

        load_block(file, block_str, pos, BLOCK_SIZE);
        print_bytes(block,BLOCK_SIZE,0);
        decrypt_block(block, BLOCK_SIZE, do_cbc, _IV);
        print_bytes(block,BLOCK_SIZE,0);
        write_block(file, block_str, pos, BLOCK_SIZE);

    } // does not update IV

}

void load_block(fstream &file, char block_str[], const int pos, const int size){
    file.seekg(pos, ios::beg);
    file.read(block_str, size);
}

void write_block(fstream &file, char block_str[], const int pos, const int size){
    file.seekg(pos, ios::beg);
    file.write(block_str, size);
}