# Kyle Stolle - CSCE 463 Final Projecct: AES vs RSA 04/26/2020
# This program will be used to encrypt and decrypt data using AES-CBC

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes as grb
import random

class aes:
    def __init__(self, **kwargs):
        self.key = self.setKey()
        self.iv = self.setIV()

    def setKey(self):
        key = grb(32)
        return key

    def setIV(self):
        iv = grb(16)
        return iv
    
    def getKey(self):
        return self.key
    
    def getIV(self):
        return self.iv

    def encrypt(self,plaintext):
        enc = AES.new(self.key,AES.MODE_CBC,self.iv)
        return enc.encrypt(plaintext)

    def decrypt(self,ciphertext):
        dec = AES.new(self.key,AES.MODE_CBC,self.iv)
        return dec.decrypt(ciphertext)

def runTest():
    import data_reader as dr
    crypt = aes()
    tenPhrases = dr.readFile("../Data/ten.txt")
    hundredPhrases = dr.readFile("../Data/hundred.txt")
    thousandPhrases = dr.readFile("../Data/thousand.txt")
    hundredThousandPhrases = dr.readFile("../Data/hundredThousand.txt")
    if(testNum(tenPhrases,crypt)):
        print("Encryption and Decryption successful for 10 phrases.")
    if(testNum(hundredPhrases,crypt)):
        print("Encryption and Decryption successful for 100 phrases.")
    if(testNum(thousandPhrases,crypt)):
        print("Encryption and Decryption successful for 1000 phrases.")
    

def testNum(phrases,c):
    # encrypting
    cipherPhrases = encryptPhrases(phrases,c)
    # decrypting
    recoveredPhrases = decryptPhrases(cipherPhrases,c)
    # test for equality 
    if(checkEquality(phrases,recoveredPhrases)):
        return True
    else:
        return False

def encryptPhrases(phrases,c):
    encryptedPhrases = []
    for phrase in phrases:
        phrase = phrase.encode(encoding='UTF-8',errors='strict')
        plaintext = pad(phrase,16)
        ciphertext = c.encrypt(plaintext)
        encryptedPhrases.append(ciphertext)

    return encryptedPhrases

def decryptPhrases(phrases,c):
    decryptedPhrases = []
    for line in phrases:
        recoveredText = c.decrypt(line)
        recoveredText = unpad(recoveredText,16)
        recoveredText = recoveredText.decode('UTF-8',errors='strict')
        decryptedPhrases.append(recoveredText)

    return decryptedPhrases 
    
def checkEquality(plain,recovered):
    i = 0
    while i < len(plain):
        if(plain[i] != recovered[i]):
            print("Line: " + i + "Plain Text: " + plain[i] + ", Recovered Text: " + recovered[i])
            return False
        i = i + 1
    return True
    

runTest()

    



