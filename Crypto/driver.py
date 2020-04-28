# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/28/2020
# This program will be used to run both algorithms while recording runtimes and then displaying the results.

from AES import aes 
import rsa
import data_reader as dr 
import data_writer as dw 
from Crypto.Util.Padding import pad, unpad

def runAES(small,med,large,five):
    crypt = aes()
    # small
    aesSmall(small,crypt)
    # med 
    aesMed(med,crypt)
    # large
    aesLarge(large,crypt)
    # five thousand
    aesFiveThousand(five,crypt)

def runRSA(small,med,large):
    # small 
    rsaSmall(small)
    print()
    rsaMed(med)
    print()
    rsaLarge(large)

def rsaSmall(small):
    pksmall = rsa.getPubKey1024()
    sksmall = rsa.getSecretKey1024()
    print("RSA Encrypting up to 117-byte strings")
    cipher = rsa.encryptPhrases(small,pksmall)
    print("RSA Decrypting up to 117-byte strings")
    recoverd = rsa.decryptPhrases(cipher,sksmall)
    print("RSA Done with Encryption and Decryption of 117-byte strings")

def rsaMed(med):
    pkmed = rsa.getPubKey2048()
    skmed = rsa.getSecretKey2048()
    print("RSA Encrypting up to 245-byte strings")
    cipher = rsa.encryptPhrases(med,pkmed)
    print("RSA Decrypting up to 245-byte strings")
    recoverd = rsa.decryptPhrases(cipher,skmed)
    print("RSA Done with Encryption and Decryption of 245-byte strings")

def rsaLarge(large):
    pklarge = rsa.getPubKey4096()
    sklarge = rsa.getSecretKey4096()
    print("RSA Encrypting up to 468-byte strings")
    cipher = rsa.encryptPhrases(large,pklarge)
    print("RSA Decrypting up to 468-byte strings")
    recoverd = rsa.decryptPhrases(cipher,sklarge)
    print("RSA Done with Encryption and Decryption of 468-byte strings")

def aesSmall(small,crypt):
    print("AES Encrypting up to 117-byte Strings")
    sCiphers = encryptPhrases(small,crypt)
    print("AES Decrypting up to 117-byte strings")
    sRecovered = decryptPhrases(sCiphers,crypt)
    print("AES Done with Encryption and Decryption of 117-byte strings")
    print(small[3],sCiphers[3],sRecovered[3])

def aesMed(med,crypt):
    print("AES Encrypting up to 245-byte Strings")
    mCiphers = encryptPhrases(med,crypt)
    print("AES Decrypting up to 245-byte strings")
    mRecovered = decryptPhrases(mCiphers,crypt)
    print("AES Done with Encryption and Decryption of 245-byte strings")
    print(med[3],mCiphers[3],mRecovered[3])

def aesLarge(large,crypt):
    print("AES Encrypting up to 468-byte Strings")
    lCiphers = encryptPhrases(large,crypt)
    print("AES Decrypting up to 468-byte strings")
    lRecovered = decryptPhrases(lCiphers,crypt)
    print("AES Done with Encryption and Decryption of 468-byte strings")
    print(large[3],lCiphers[3],lRecovered[3])

def aesFiveThousand(five,crypt):
    print("AES Encrypting strings up to 5,000")
    ciphers = encryptPhrases(five,crypt)
    print("AES Decrypting up to 468-byte strings")
    recoverd = decryptPhrases(ciphers,crypt)
    print("AES Done with Encryption and Decryption of 5000 strings with max string length = 5000")
    print(five[5],ciphers[5],recoverd[5])
    
def encryptPhrases(phrases,c):
    encryptedPhrases = []
    for phrase in phrases:
        plaintext = pad(phrase,16)
        ciphertext = c.encrypt(plaintext)
        encryptedPhrases.append(ciphertext)

    return encryptedPhrases

def decryptPhrases(phrases,c):
    decryptedPhrases = []
    for line in phrases:
        recoveredText = c.decrypt(line)
        recoveredText = unpad(recoveredText,16)
        decryptedPhrases.append(recoveredText)

    return decryptedPhrases

# writing
dw.write117bytes()
dw.write245bytes()
dw.write468bytes()
# reading 
small = dr.readFile("../Data/117.txt")
med = dr.readFile("../Data/245.txt")
large = dr.readFile("../Data/468.txt")
fiveThousand = dr.readFile("../Data/fiveThousand.txt")
# time holders 
aesSmallTimes = []
aesMedTimes = []
aesLargeTimes = []
aesFiveTimes = []

rsaSmallTimes = []
rsaMedTimes = [] 
rsaLargeTimes = []

runAES(small,med,large,fiveThousand)
print()
print()
runRSA(small,med,large)