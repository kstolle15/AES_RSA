# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/28/2020
# This program will be used to run both algorithms while recording runtimes and then displaying the results.

from AES import aes 
import rsa
import data_reader as dr 
import data_writer as dw 
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import datetime

def runAES(small,med,large):
    crypt = aes()
    # small
    smallStart = datetime.datetime.now()
    aesSmall(small,crypt)
    smallEnd = datetime.datetime.now()
    aesSmallTimes.append(smallEnd - smallStart)    
    # med 
    medStart = datetime.datetime.now()
    aesMed(med,crypt)
    medEnd = datetime.datetime.now()
    aesMedTimes.append(medEnd - medStart)
    # large
    largeStart = datetime.datetime.now()
    aesLarge(large,crypt)
    largeEnd = datetime.datetime.now()
    aesLargeTimes.append(largeEnd-largeStart)

def runRSA(small,med,large):
    # small 
    smallStart = datetime.datetime.now()
    rsaSmall(small)
    smallEnd = datetime.datetime.now()
    rsaSmallTimes.append(smallEnd-smallStart)

    medStart = datetime.datetime.now()
    rsaMed(med)
    medEnd = datetime.datetime.now()
    rsaMedTimes.append(medEnd - medStart)
    
    largeStart = datetime.datetime.now()
    rsaLarge(large)
    largeEnd = datetime.datetime.now()
    rsaLargeTimes.append(largeEnd - largeStart)

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

# time holders 
aesSmallTimes = []
aesMedTimes = []
aesLargeTimes = []
aesFiveTimes = []

rsaSmallTimes = []
rsaMedTimes = []
rsaLargeTimes = []

# run algorithms 10 times for new data each run 
for i in range(1,11):
    print("Running Test " + str(i))
    # writing
    dw.write117bytes()
    dw.write245bytes()
    dw.write468bytes()
    # reading 
    small = dr.readFile("../Data/117.txt")
    med = dr.readFile("../Data/245.txt")
    large = dr.readFile("../Data/468.txt")
    print("Runing AES Encryption and Decryption for Test " + str(i))
    runAES(small,med,large)
    print()
    print("Runing RSA Encryption and Decryption for Test " + str(i))
    runRSA(small,med,large)

print(aesLargeTimes)
print(rsaLargeTimes)
# converting microseconds to seconds 
# small conversions 
for i in range(0,10):
    if(aesSmallTimes[i].seconds < 1):
        aesSmallTimes[i] = aesSmallTimes[i].microseconds/1000000 # convert microseconds to miliseconds
    else:
        aesSmallTimes[i] = aesSmallTimes[i].seconds + (aesSmallTimes[i].microseconds/1000000)
    if(rsaSmallTimes[i].seconds < 1):
        rsaSmallTimes[i] = rsaSmallTimes[i].microseconds/1000000 # convert microseconds to miliseconds
    else:
        rsaSmallTimes[i] = rsaSmallTimes[i].seconds + (rsaSmallTimes[i].microseconds/1000000)
# med conversions 
for i in range(0,10):
    if(aesMedTimes[i].seconds < 1):
        aesMedTimes[i] = aesMedTimes[i].microseconds/1000000 # convert microseconds to miliseconds
    else:
        aesMedTimes[i] = aesMedTimes[i].seconds + (aesMedTimes[i].microseconds/1000000)
    if(rsaMedTimes[i].seconds < 1):
        rsaMedTimes[i] = rsaMedTimes[i].microseconds/1000000 # convert microseconds to miliseconds
    else:
        rsaMedTimes[i] = rsaMedTimes[i].seconds + (rsaMedTimes[i].microseconds/1000000)
# large conversions
for i in range(0,10):
    if(aesLargeTimes[i].seconds < 1):
        aesLargeTimes[i] = aesLargeTimes[i].microseconds/1000000 # convert microseconds to miliseconds
    else:
        aesLargeTimes[i] = aesLargeTimes[i].seconds + (aesLargeTimes[i].microseconds/1000000)
    if(rsaLargeTimes[i].seconds < 1):
        rsaLargeTimes[i] = rsaLargeTimes[i].microseconds/1000000 # convert microseconds to miliseconds
    else:
        rsaLargeTimes[i] = rsaLargeTimes[i].seconds + (rsaLargeTimes[i].microseconds/1000000)

print(aesLargeTimes)
print(rsaLargeTimes)