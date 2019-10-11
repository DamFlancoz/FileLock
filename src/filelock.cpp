#include <iostream>
#include <fstream>
#include "aes.h"
#include "aes.cpp"

#define READ_SIZE 16/sizeof(char)

using namespace std;

// Globals

static union {
    byte block[16];
    char block_str[READ_SIZE];
};

fstream file;
int file_size;

int main(int argc, char* argv[]){

    if (argc != 6 && argc != 7) {

        cerr << "Please use (ECB mode): aes <-r/-f> <-e/-d> <128/192/256> <key> <text>" << endl;
        cerr << "or" << endl;
        cerr << "Please use (CBC mode): aes <-r/-f> <-e/-d> <128/192/256> <key> <IV> <text>" << endl;
        cerr << "Note, for decryption IV may be 0 or anything non-empty"<< endl;
        exit(1);
    }

    // Encrypt or decrypt flag
    const bool raw = argv[1][1] == 'r';
    const bool flag_e = argv[2][1] == 'e';

    // check CBC
    do_cbc = (argc == 7);
    if (do_cbc && flag_e) stob(IV, argv[5], 16);

    // Get key and expand it.
    key_size = atoi(argv[3]);

    byte key[key_size/8];
    stob(key, argv[4], key_size/8);

    expand_key(expanded_key, key);

    // Get File
    const char* file_path = do_cbc ? argv[6] : argv[5];

    file.open("test.txt",ios::in|ios::out|ios::out|ios::binary|ios::ate);

    if (file.is_open()){

        file_size = file.tellg();

        file.seekg(0, ios::beg);

    } else {
        cout << "Did not open." << endl;
        exit(1);
    }

    // Process
    if (flag_e){
        // encrypt(text, text_size);
        // print_bytes(text, text_size, raw);
        // decrypt(text, text_size);
        // print_bytes(&text[((do_cbc&& flag_e)?16:0)], text_size - ((do_cbc && flag_e)?16:0), raw);

    } else {

        // decrypt(text, text_size);
        // print_bytes(&text[(do_cbc?16:0)], text_size - (do_cbc?16:0), raw);
    }

    return 0;
}

int load_next_block(){
    file.read(block_str, READ_SIZE);
    return file.tellg() - READ_SIZE;
}

int write_block(int pos){
    file.seekg(0, ios::beg);
    file.write(block_str, READ_SIZE);
}