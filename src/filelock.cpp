#include <iostream>
#include <fstream>

#include "aes.h"

using namespace std;

void encrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc, const byte IV[16]);
void decrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc);

void load_block(fstream &file, byte block[], const int &pos, const int &size);
void write_block(fstream &file, const byte block[], const int &pos, const int &size);

int main(int argc, char* argv[]){

    // TODO: Add raise error function to handle all error messages.

    if (argc != 5 && argc != 6) {

        cerr << "Please use (ECB mode): aes <-e/-d> <128/192/256> <key> <file>" << endl;
        cerr << "or" << endl;
        cerr << "Please use (CBC mode): aes <-e/-d> <128/192/256> <key> <IV> <file>" << endl;
        cerr << "Note, for decryption IV may be 0 or anything non-empty"<< endl;
        exit(1);
    }

    // Encrypt or decrypt flag
    const bool flag_e = argv[1][1] == 'e';

    // check CBC, IV is given if cbc is to be done
    const bool do_cbc = (argc == 6);
    byte IV[BLOCK_SIZE];
    if (do_cbc) aes::stob(IV, argv[4], BLOCK_SIZE);

    // Get key and expand it.
    aes::key_size = atoi(argv[2]);

    byte key[aes::key_size/8];
    aes::stob(key, argv[3], aes::key_size/8);

    aes::expand_key(aes::expanded_key, key);

    // Get Input File
    const string in_file_path = do_cbc ? argv[5] : argv[4];

    fstream in_file (in_file_path, ios::in|ios::binary|ios::ate);

    if (!in_file.is_open()){
        cout << "File could not be openned" << endl;
        exit(2);
    }

    int file_size = in_file.tellg();
    in_file.seekg(0, ios::beg);

    // Get Output File
    auto get_out_file_path = [flag_e, in_file_path]() {
        if (flag_e)
            return in_file_path + ".aes";
        else
            return in_file_path.substr(0, in_file_path.length()-4);
    };

    fstream out_file (get_out_file_path(), ios::out|ios::binary);

    // Process
    if (flag_e)
        encrypt(in_file, out_file, file_size, do_cbc, IV);
    else
        decrypt(in_file, out_file, file_size, do_cbc);

    // Clean up
    in_file.close();
    out_file.close();

    return 0;
}

void encrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc, const byte IV[BLOCK_SIZE]){
    byte block[BLOCK_SIZE];
    byte to_xor[BLOCK_SIZE];
    int pos;

    if (do_cbc) {
        aes::mov(to_xor, IV, BLOCK_SIZE);
        write_block(out_file, IV, 0, BLOCK_SIZE);
    }

    for (pos=0; pos<=file_size-BLOCK_SIZE; pos+=BLOCK_SIZE){

        load_block(in_file, block, pos, BLOCK_SIZE);

        aes::encrypt_block(block, do_cbc, to_xor);

        write_block(out_file, block, pos + (do_cbc?BLOCK_SIZE:0), BLOCK_SIZE);

        if (do_cbc) aes::mov(to_xor, block, BLOCK_SIZE);

    } // append IV and padding info at end

    const byte load_size = file_size-pos; // number of bytes in last block

    load_block(in_file, block, pos, BLOCK_SIZE);

    // add padding of zeros
    for (int i=load_size; i<=file_size; i++) block[i]=0;

    aes::encrypt_block(block, do_cbc, to_xor);

    write_block(out_file, block, pos + (do_cbc?BLOCK_SIZE:0), BLOCK_SIZE);

    // add number of padding at the end
    write_block(out_file, &load_size, pos + BLOCK_SIZE + (do_cbc?BLOCK_SIZE:0), 1);
}

void decrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc){
    byte block[BLOCK_SIZE];
    byte to_xor[BLOCK_SIZE];
    byte temp[BLOCK_SIZE];
    int pos;

    // Assumes first block to be IV
    if (do_cbc) load_block(in_file, to_xor, 0, BLOCK_SIZE);

    for (pos=do_cbc?BLOCK_SIZE:0; pos<file_size-BLOCK_SIZE-1; pos+=BLOCK_SIZE){

        load_block(in_file, block, pos, BLOCK_SIZE);
        if (do_cbc) aes::mov(temp, block, BLOCK_SIZE);

        aes::decrypt_block(block, do_cbc, to_xor);
        if (do_cbc) aes::mov(to_xor, temp, BLOCK_SIZE);

        write_block(out_file, block, pos - (do_cbc?BLOCK_SIZE:0), BLOCK_SIZE);

    } // does not update IV

    load_block(in_file, block, pos, BLOCK_SIZE);

    // write ignoring the padding
    int write_size = [&](){
        byte temp;
        load_block(in_file, &temp, pos + BLOCK_SIZE, 1);
        return temp;
    }();

    aes::decrypt_block(block, do_cbc, to_xor);

    write_block(out_file, block, pos - (do_cbc?BLOCK_SIZE:0), write_size);
}

void load_block(fstream &file, byte block[], const int &pos, const int &size){
    if (!size) return;

    file.seekg(pos, ios::beg);
    file.read((char*)block, size);

    cout << "Read: ";
    aes::print_bytes(block, size);
}

void write_block(fstream &file, const byte block[], const int &pos, const int &size){
    if (!size) return;

    file.seekg(pos, ios::beg);
    file.write((char*)block, size);

    cout << "Write: ";
    aes::print_bytes(block, size);
}