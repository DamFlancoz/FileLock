#include <iostream>
#include <fstream>

using namespace std;

int main(){
    // use boost filesystem or rename/remove in stdio (take cstrings)
    // first always the name of program is given in arg
    fstream f ("test.txt",ios::in|ios::out|ios::binary|ios::ate);

    if (f.is_open()){
        // ios::ate positions pointer to end of file and
        // tellg tells its position
        int size = f.tellg();

        char block_[size];
        byte block[size];

        // place pointer at start, read
        f.seekg(0, ios::beg);
        f.read(block_, size);

        cout << block_ << endl;
        cout << "Size: " << size << endl;

        // transfer, convert to byte
        for(int i=0; i<size; i++){
            block[i]=(byte)block_[i];
        }

        // operation
        // and print were here

        // transfer/convert back
        for(int i=0; i<size; i++){
            block_[i]=(char)block[i];
        }

        // reset pointer and overwrite.
        f.seekg(0, ios::beg);
        f.write(block_, size);
        f.close();
    } else {
        cout << "Did not open." << endl;
    }
}