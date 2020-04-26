# Kyle Stolle - CSCE 463 Final Projecct: AES vs RSA 04/26/2020
# This program will be used to encrypt and decrypt data using AES-CBC

from Crypto.Cipher import AES
from Crypto.Util import Padding
import data_reader

class aes:
    def __init__(self):
        self.key = setKey()
        self.iv = setIV()

    def setKey():
        key = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        return key

    def setIV():
        iv = ''.join(chr(random.randint(0,0xFF)) for i in range(16))
    
    def getKey():
        return self.key
    
    def getIV():
        return self.iv

    def encrypt(plaintext):
        enc = AES.new(self.key,AES.MODE_CBC,self.iv)
        return enc.encrypt(plaintext.encode())

    def decrypt(ciphertext):
        dec = AES.new(self.key,AES.MODE_CBC,self.iv)
        return dec.decrypt(ciphertext)




