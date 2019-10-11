"""Temporary main file to get things working"""

import os
from datetime import datetime
from hashlib import shake_256
import subprocess

import click

aes = './aes.exe'

'''
bytes.fromhex('41').decode()

m=subprocess.Popen(args)
stdout, err = m.communicate()

TODO Make encrypt_file.cpp instead, arguments have max limit.
'''

def pad32(s):
    aim = (1 + len(s) // 16)*16
    pad = aim - len(s)

    return s.ljust(aim,'0') + str(pad).zfill(16)

def depad32(s):
    pad = int(s[-16:])
    return s[:-16-pad]

@click.command()
@click.argument('aes_key_len')
@click.argument('password')
@click.argument('target')
@click.option('-e','do_encrypt', is_flag=True, default=False, help="Do encryption")
@click.option('-d','do_decrypt', is_flag=True, default=False, help="Do decryption")
@click.option('--cbc','do_cbc',is_flag=True,default=True)
@click.option('--ebc','do_ebc',is_flag=True,default=False)
def main(target, password, aes_key_len, do_cbc, do_ebc, do_encrypt, do_decrypt):

    aes_key = shake_256(password.encode()).hexdigest(int(aes_key_len)//8)

    flag = '-e' if do_encrypt else '-d' if do_decrypt else None
    if flag is None:
        #Error
        print("Required flag: -e or -d")
        return

    if do_ebc: do_cbc = False

    now_str = str(datetime.now())
    IV = shake_256(now_str.encode()).hexdigest(16)

    if os.path.isfile(target):
        with open(target, 'rb') as f:
            content = f.read().decode()

        if flag == '-e':
            # print(pad32(content).encode().hex())
            content = pad32(content).encode().hex()
        args = [aes,'-r', flag, aes_key_len, aes_key]+ ([IV] if do_cbc else []) + [content]
        print(aes)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        processed_content, err = p.communicate()

        if flag == '-d':
            # print(depad32(bytes.fromhex(processed_content.decode())))
            processed_content = depad32(bytes.fromhex(processed_content.decode()))

        if err is None:
            with open(target, 'wb') as f:
                f.write(processed_content)

if __name__ == '__main__':
    main()
