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
'''

@click.command()
@click.argument('aes_key_len')
@click.argument('password')
@click.argument('target')
@click.option('-e','do_encrypt', is_flag=True, default=True)
@click.option('--cbc','do_cbc',is_flag=True,default=True)
def main(target, password, aes_key_len, do_cbc, do_encrypt):

    aes_key = shake_256(password.encode()).hexdigest(int(aes_key_len)//8)
    flag = '-e' if do_encrypt else '-d'

    now_str = str(datetime.now())
    IV = shake_256(now_str.encode()).hexdigest(16)

    if os.path.isfile(target):
        with open(target, 'rb') as f:
            content = f.read().decode()

        args = [aes,'-r', flag, aes_key_len, aes_key]+ ([IV] if do_cbc else []) + [content]
        print(args)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        encrypted, err = p.communicate()

        if err is None:
            with open(target, 'wb') as f:
                f.write(encrypted)
            print(encrypted)

if __name__ == '__main__':
    main()

