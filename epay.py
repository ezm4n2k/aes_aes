from email.mime import base
from Crypto.Cipher import AES
from os import urandom
import binascii
import os
import pyaes
import os
import base64
import codecs
from argparse import ArgumentParser

password = 'BA99FDF9FEEC1EF9896DE9BF00CF27C4'
key = bytes(password, 'utf-8')

def decrypt(data):
    # string = "4+qTBjU+oXP5pvG9j0lQa9g5eNfBbzyaD/o6DcxZcvY3LNnN5VAZ3W3dv+VeXmXpUCH1spqFFzf+PAPKaes4+C8c6q89/n2ICQJnJjn/t/O9jKcB2kwI/Qa8dnyFRMDbYYAHnkZr8nw7KZIv99SQ75EKrSjSIG0CQhHqGrTfgFnMI/ESRnzNRt6aXqolX6osdN+9msZuAcU1rV6QTrpGF9nVp5s="
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
    # message = '{"State":1,"MsgID":"fb1a18657fc152ff18-09-2022 22:08:34.593","MsgType":"smartotp_check_active_response","TransactionID":"16635533145937482"}'
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
    