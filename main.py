from os import urandom
import binascii
import pyaes
import os
import base64
import codecs
from argparse import ArgumentParser

password = 'BA99FDF9FEEC1EF9896DE9BF00CF27C4'
key = bytes(password, 'utf-8')

def decrypt(data):
    a = base64.b64decode(data)
    ival = a[0:16]
    iv = int.from_bytes(ival, "big")
    cipher = a[16:len(a)]
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(cipher)
    result=binascii.hexlify(decrypted).decode('utf-8')
    result_=bytes(result, encoding='utf-8')
    _result_=codecs.decode(result_,"hex")
    return(str(_result_,'utf-8'))

def encrypt(data):
    ival= os.urandom(16)
    iv = int.from_bytes(ival, "big")
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    encrypted= aes.encrypt(data)
    c= ival+encrypted
    result=base64.b64encode(c)
    return(result.decode())

def read_config():
    parser = ArgumentParser()
    parser.add_argument("-i", "--input", help="Input File", required=True)
    parser.add_argument("-m", "--mode", help="decrypt or encrypt", choices=['e', 'd'], required=True)
    parser.add_argument("-o", "--output", help="Output File", required=True)
    args = parser.parse_args()
    input_file = str(args.input)
    output_file = str(args.output)
    mode = str(args.mode)
    return [input_file, output_file, mode]
    
if __name__ == "__main__":
    input_file, output_file, mode = read_config()
    results = []
    datas = []
    with open(input_file, "rb") as f:
        datas=f.readlines()
    for data in datas:
        if mode =="e":
            results.append(encrypt(data))
        elif mode =="d":
            results.append(decrypt(data))
    with open(output_file, 'w', encoding='utf-8') as fp:
        for result in results:
            fp.write("%s\n" % result)
    print('Done!!')
