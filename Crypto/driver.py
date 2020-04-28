# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/28/2020
# This program will be used to run both algorithms while recording runtimes and then displaying the results.

from AES import aes 
import rsa
import data_reader as dr 
import data_writer as dw 
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import datetime

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
    rsaMed(med)
    rsaLarge(large)

def rsaSmall(small):
    pksmall = rsa.getPubKey1024()
    sksmall = rsa.getSecretKey1024()
    print("RSA Encrypting up to 117-byte strings")
    cipher = rsaEncryptPhrases(small,pksmall)
    recoverd = rsaDecryptPhrases(cipher,sksmall)

def rsaMed(med):
    pkmed = rsa.getPubKey2048()
    skmed = rsa.getSecretKey2048()
    print("RSA Encrypting up to 245-byte strings")
    cipher = rsaEncryptPhrases(med,pkmed)
    recoverd = rsaDecryptPhrases(cipher,skmed)

def rsaLarge(large):
    pklarge = rsa.getPubKey4096()
    sklarge = rsa.getSecretKey4096()
    print("RSA Encrypting up to 468-byte strings")
    cipher = rsaEncryptPhrases(large,pklarge)
    recoverd = rsaDecryptPhrases(cipher,sklarge)

def aesSmall(small,crypt):
    print("AES Encrypting up to 117-byte Strings")
    sCiphers = aesEncryptPhrases(small,crypt)
    sRecovered = aesDecryptPhrases(sCiphers,crypt)

def aesMed(med,crypt):
    print("AES Encrypting up to 245-byte Strings")
    mCiphers = aesEncryptPhrases(med,crypt)
    mRecovered = aesDecryptPhrases(mCiphers,crypt)

def aesLarge(large,crypt):
    print("AES Encrypting up to 468-byte Strings")
    lCiphers = aesEncryptPhrases(large,crypt)
    lRecovered = aesDecryptPhrases(lCiphers,crypt)

def aesFiveThousand(five,crypt):
    print("AES Encrypting strings up to 5,000")
    ciphers = aesEncryptPhrases(five,crypt)
    recoverd = aesDecryptPhrases(ciphers,crypt)
    
def aesEncryptPhrases(phrases,c):
    encryptedPhrases = []
    for phrase in phrases:
        plaintext = pad(phrase,16)
        ciphertext = c.encrypt(plaintext)
        encryptedPhrases.append(ciphertext)

    return encryptedPhrases

def aesDecryptPhrases(phrases,c):
    decryptedPhrases = []
    for line in phrases:
        recoveredText = c.decrypt(line)
        recoveredText = unpad(recoveredText,16)
        decryptedPhrases.append(recoveredText)

    return decryptedPhrases

def rsaEncryptPhrases(phrases,key):
    cipher = []
    e = PKCS1_OAEP.new(key)
    for line in phrases:
        ciphertext = e.encrypt(line)
        cipher.append(ciphertext)
    return cipher

def rsaDecryptPhrases(phrases,key):
    recover = []
    d = PKCS1_OAEP.new(key)
    for line in phrases:
        recoveredtext = d.decrypt(line)
        recover.append(recoveredtext)
    
    return recover

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

aesStart = datetime.datetime.now()
runAES(small,med,large,fiveThousand)
aesEnd = datetime.datetime.now()
aesTotal = aesEnd - aesStart
print(str(aesTotal.seconds) + "." + str(aesTotal.microseconds) + " seconds")
print()
print()
rsaStart = datetime.datetime.now()
runRSA(small,med,large)
rsaEnd = datetime.datetime.now()
totalRSA = rsaEnd - rsaStart
print(str(totalRSA.seconds) + "." + str(totalRSA.microseconds) + " seconds")