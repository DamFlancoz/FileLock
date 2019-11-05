#include <iostream>
#include <fstream>
#include <cstring>

#include "aes.cpp"

using namespace std;

void encrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc, const byte IV[16]);
void decrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc, const byte IV[16]);

void load_block(fstream &file, byte block[], const int &pos, const int &size);
void write_block(fstream &file, const byte block[], const int &pos, const int &size);

// Globals

int main(int argc, char* argv[]){

    // TODO: adding padding functionality
    // Currently drops the last block

    if (argc != 5 && argc != 6) {

        cerr << "Please use (ECB mode): aes <-e/-d> <128/192/256> <key> <text>" << endl;
        cerr << "or" << endl;
        cerr << "Please use (CBC mode): aes <-e/-d> <128/192/256> <key> <IV> <text>" << endl;
        cerr << "Note, for decryption IV may be 0 or anything non-empty"<< endl;
        exit(1);
    }

    // Encrypt or decrypt flag
    const bool flag_e = argv[1][1] == 'e';

    // check CBC, IV is given if cbc is to be done
    const bool do_cbc = (argc == 6);
    byte IV[BLOCK_SIZE];
    if (do_cbc) stob(IV, argv[4], BLOCK_SIZE);

    // Get key and expand it.
    key_size = atoi(argv[2]);

    byte key[key_size/8];
    stob(key, argv[3], key_size/8);

    expand_key(expanded_key, key);
    // cout << "Key: ";
    // print_bytes(key,key_size/8,0);
    // print_bytes(expanded_key, 160+16);

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
        decrypt(in_file, out_file, file_size, do_cbc, IV);

    // Clean up
    in_file.close();
    out_file.close();

    return 0;
}

void encrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc, const byte IV[BLOCK_SIZE]){
    byte block[BLOCK_SIZE];
    byte to_xor[BLOCK_SIZE];

    if (do_cbc) {
        mov(to_xor, IV, BLOCK_SIZE);
        write_block(out_file, IV, 0, BLOCK_SIZE);
    }

    for (int pos=0; pos<=file_size-BLOCK_SIZE; pos+=BLOCK_SIZE){

        load_block(in_file, block, pos, BLOCK_SIZE);

        encrypt_block(block, do_cbc, to_xor);

        write_block(out_file, block, pos + (do_cbc?BLOCK_SIZE:0), BLOCK_SIZE);

        if (do_cbc) mov(to_xor, block, BLOCK_SIZE);
    } // append IV and padding info at end

    cout << endl;

}

void decrypt(fstream &in_file, fstream &out_file, const int &file_size, const bool &do_cbc, const byte IV[BLOCK_SIZE]){
    byte block[BLOCK_SIZE];
    byte to_xor[BLOCK_SIZE];
    byte temp[BLOCK_SIZE];

    if (do_cbc) load_block(in_file, to_xor, 0, BLOCK_SIZE);

    for (int pos=do_cbc?BLOCK_SIZE:0; pos<=file_size-BLOCK_SIZE; pos+=BLOCK_SIZE){

        load_block(in_file, block, pos, BLOCK_SIZE);
        if (do_cbc) mov(temp, block, BLOCK_SIZE);

        decrypt_block(block, do_cbc, to_xor);
        if (do_cbc) mov(to_xor, temp, BLOCK_SIZE);

        write_block(out_file, block, pos - (do_cbc?BLOCK_SIZE:0), BLOCK_SIZE);

    } // does not update IV

}

void load_block(fstream &file, byte block[], const int &pos, const int &size){
    file.seekg(pos, ios::beg);
    file.read((char*)block, size);
    cout << "Read: ";
    print_bytes(block);
}

void write_block(fstream &file, const byte block[], const int &pos, const int &size){
    file.seekg(pos, ios::beg);
    file.write((char*)block, size);
    cout << "Write: ";
    print_bytes(block);
}