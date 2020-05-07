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

def runAES(s,m,l):
    small = aes()
    med = aes()
    large = aes()

    # 117-byte
    smallstart = datetime.datetime.now()
    smallCiphers = small.encryptPhrases(s)
    smallRecovered = small.decryptPhrases(smallCiphers)
    smallend = datetime.datetime.now()
    smalltotal = smallend - smallstart 
    smalltotal = smalltotal.seconds + (smalltotal.microseconds/1000000)
    aesTotals[0] += smalltotal
    avgD = small.calcAverage(small.converToSeconds(small.decryptTimes))
    avgE = small.calcAverage(small.converToSeconds(small.encryptTimes))
    aesEncryptionAverages[0] += avgE
    aesDecryptionAverages[0] += avgD
    # 245 byte
    medstart = datetime.datetime.now()
    medCiphers = med.encryptPhrases(m)
    medRecovered = med.decryptPhrases(medCiphers)
    medend = datetime.datetime.now()
    medtotal = medend - medstart
    medtotal = medtotal.seconds + (medtotal.microseconds/1000000)
    aesTotals[1] += medtotal
    avgD = med.calcAverage(med.converToSeconds(med.decryptTimes))
    avgE = med.calcAverage(med.converToSeconds(med.encryptTimes))
    aesEncryptionAverages[1] += avgE
    aesDecryptionAverages[1] += avgD
    # 468-byte
    largestart = datetime.datetime.now()
    largeCiphers = large.encryptPhrases(l)
    largeRecovered = large.decryptPhrases(largeCiphers)
    largeend = datetime.datetime.now()
    largetotal = largeend - largestart
    largetotal = largetotal.seconds + (largetotal.microseconds/1000000)
    aesTotals[2] += largetotal
    avgD = large.calcAverage(large.converToSeconds(large.decryptTimes))
    avgE = large.calcAverage(large.converToSeconds(large.encryptTimes))
    aesEncryptionAverages[2] += avgE
    aesDecryptionAverages[2] += avgD


aesEncryptionAverages = [0,0,0]
aesDecryptionAverages = [0,0,0]
aesTotals = [0,0,0]

for i in range(1,11):
    print("Running test " + str(i))
    dw.write117bytes()
    dw.write245bytes()
    dw.write468bytes()

    small = dr.readFile("../Data/117.txt")
    med = dr.readFile("../Data/245.txt")
    large = dr.readFile("../Data/468.txt")
    print("Running AES Encryption and Decryption")
    runAES(small,med,large)
    print()

# average everything
for i in range(0,3):
    aesEncryptionAverages[i] = aesEncryptionAverages[i]/10
    aesDecryptionAverages[i] = aesDecryptionAverages[i]/10
    aesTotals[i] = aesTotals[i]/10

print(aesEncryptionAverages)
print(aesDecryptionAverages)
print(aesTotals)

"""
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
plt.show()"""
