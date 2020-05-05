# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/28/2020
# This program will be used to run both algorithms while recording runtimes and then displaying the results.

from AES import aes 
import rsa
import data_reader as dr 
import data_writer as dw 
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import datetime
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def runAES(small,med,large):
    cryptOne = aes()
    cryptTwo = aes()
    cryptThree = aes()
    # small
    smallStart = datetime.datetime.now()
    aesSmall(small,cryptOne)
    smallEnd = datetime.datetime.now()  
    cryptOne.totalTime = smallEnd - smallStart
    # med 
    medStart = datetime.datetime.now()
    aesMed(med,cryptTwo)
    medEnd = datetime.datetime.now()
    cryptTwo.totalTime = medEnd - medStart
    # large
    largeStart = datetime.datetime.now()
    aesLarge(large,cryptThree)
    largeEnd = datetime.datetime.now()
    cryptThree.totalTime = largeEnd - largeStart

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

def runModRSA(small,med,large):
    # small 
    crypt = aes()
    smallStart = datetime.datetime.now()
    modrsaSmall(small,crypt)
    smallEnd = datetime.datetime.now()
    modRsaSmallTimes.append(smallEnd - smallStart)

    # med 
    medStart = datetime.datetime.now()
    modrsaMed(med,crypt)
    medEnd = datetime.datetime.now()
    modRsaMedTimes.append(medEnd - medStart)

    # large
    largeStart = datetime.datetime.now()
    modrsaLarge(large,crypt)
    largeEnd = datetime.datetime.now()
    modRsaLargeTimes.append(largeEnd - largeStart) 

def rsaSmall(small):
    pksmall = rsa.getPubKey1024()
    sksmall = rsa.getSecretKey1024()
    print("RSA 117-byte Encrypting")
    cipher = rsaEncryptPhrases(small,pksmall)
    recoverd = rsaDecryptPhrases(cipher,sksmall)

def rsaMed(med):
    pkmed = rsa.getPubKey2048()
    skmed = rsa.getSecretKey2048()
    print("RSA 245-byte Encrypting")
    cipher = rsaEncryptPhrases(med,pkmed)
    recoverd = rsaDecryptPhrases(cipher,skmed)

def rsaLarge(large):
    pklarge = rsa.getPubKey4096()
    sklarge = rsa.getSecretKey4096()
    print("RSA 468-byte Encrypting")
    cipher = rsaEncryptPhrases(large,pklarge)
    recoverd = rsaDecryptPhrases(cipher,sklarge)

def modrsaSmall(small,crypt):
    pksmall = rsa.getPubKey1024()
    sksmall = rsa.getSecretKey1024()
    e = PKCS1_OAEP.new(pksmall)
    d = PKCS1_OAEP.new(sksmall)

    print("MOD-RSA 117-byte Encrypting")
    cipher = aesEncryptPhrases(small,crypt)
    crypt.key = e.encrypt(crypt.key)

    crypt.key = d.decrypt(crypt.key)
    recoverd = aesDecryptPhrases(cipher,crypt)

def modrsaMed(med,crypt):
    pkmed = rsa.getPubKey2048()
    skmed = rsa.getSecretKey2048()
    e = PKCS1_OAEP.new(pkmed)
    d = PKCS1_OAEP.new(skmed)

    print("MOD-RSA 245-byte Encrypting")
    cipher = aesEncryptPhrases(med,crypt)
    crypt.key = e.encrypt(crypt.key)

    crypt.key = d.decrypt(crypt.key)
    recoverd = aesDecryptPhrases(cipher,crypt)

def modrsaLarge(large,crypt):
    pklarge = rsa.getPubKey4096()
    sklarge = rsa.getSecretKey4096()
    e = PKCS1_OAEP.new(pklarge)
    d = PKCS1_OAEP.new(sklarge)

    print("MOD-RSA 468-byte Encrypting")
    cipher = aesEncryptPhrases(large,crypt)
    crypt.key = e.encrypt(crypt.key)

    crypt.key = d.decrypt(crypt.key)
    recoverd = aesDecryptPhrases(cipher,crypt)

def aesSmall(small,crypt):
    print("AES 117-byte Encrypting")
    sCiphers = crypt.encryptPhrases(small)
    sRecovered = crypt.decryptPhrases(sCiphers)

def aesMed(med,crypt):
    print("AES 245-byte Encrypting")
    mCiphers = crypt.encryptPhrases(med)
    mRecovered = crypt.decryptPhrases(mCiphers)

def aesLarge(large,crypt):
    print("AES RSA 468-byte Encrypting")
    lCiphers = crypt.encryptPhrases(large)
    lRecovered = crypt.decryptPhrases(lCiphers)

def aesFiveThousand(five,crypt):
    print("AES Encrypting strings up to 5,000")
    ciphers = aesEncryptPhrases(five,crypt)
    recoverd = aesDecryptPhrases(ciphers,crypt)

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

modRsaSmallTimes = []
modRsaMedTimes = []
modRsaLargeTimes = []

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
    print("Runing Modified RSA Encryption and Decryption for Test " + str(i))
    runModRSA(small,med,large)
    print()
    print("Runing RSA Encryption and Decryption for Test " + str(i))
    runRSA(small,med,large)

# graphing
dfRSA = pd.DataFrame({'x': [117,245,468], 'RSA': [rsaAverages[0],rsaAverages[1],rsaAverages[2]] })
dfAES = pd.DataFrame({'x': [117,245,468], 'AES': [aesAverages[0],aesAverages[1],aesAverages[2]] })
dfModRSA = pd.DataFrame({'x': [117,245,468], 'MOD-RSA': [modrsaAverages[0],modrsaAverages[1],modrsaAverages[2]] })
plt.plot('x','RSA', data=dfRSA, linestyle='-', marker='o',color='r')
plt.plot('x','AES', data=dfAES,linestyle = '-', marker = 'o', color='g')
plt.plot('x','MOD-RSA', data=dfModRSA,linestyle = '-', marker = 'o', color='black')

print(dfAES)
print(dfModRSA)
print(dfRSA)

# legend
plt.legend(loc=2, ncol=2)
# labels
plt.title("AES and RSA Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()
