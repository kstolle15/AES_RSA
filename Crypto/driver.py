# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/28/2020
# This program will be used to run both algorithms while recording runtimes and then displaying the results.

from AES import aes 
from rsa import rsa
from modrsa import modrsa
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

def runAESFive(five):
    crypt = aes()
    
    start = datetime.datetime.now()
    ciphers = crypt.encryptPhrases(five)
    recovered = crypt.decryptPhrases(ciphers)
    end = datetime.datetime.now()
    total = end - start
    total = total.seconds + (total.microseconds/1000000)
    totalFiveTimes[0] += total
    avgE = crypt.calcAverage(crypt.converToSeconds(crypt.encryptTimes))
    avgD = crypt.calcAverage(crypt.converToSeconds(crypt.decryptTimes))
    encryptionFiveTimes[0] += avgE
    decryptionFiveTimes[0] += avgD

def runAESThree(three):
    crypt = aes()
    
    start = datetime.datetime.now()
    ciphers = crypt.encryptPhrases(three)
    recovered = crypt.decryptPhrases(ciphers)
    end = datetime.datetime.now()
    total = end - start
    total = total.seconds + (total.microseconds/1000000)
    totalThreeTimes[0] += total
    avgE = crypt.calcAverage(crypt.converToSeconds(crypt.encryptTimes))
    avgD = crypt.calcAverage(crypt.converToSeconds(crypt.decryptTimes))
    encryptionThreeTimes[0] += avgE
    decryptionThreeTimes[0] += avgD


def runRSA(s,m,l):
    crypt = rsa()
    smallStart = datetime.datetime.now()
    c1 = crypt.encryptPhrases(s,crypt.smallpubkey)
    r1 = crypt.decryptPhrases(c1,crypt.smallseckey)
    smallEnd = datetime.datetime.now()
    crypt.totalTimes.append(smallEnd - smallStart)

    medstart = datetime.datetime.now()
    c2 = crypt.encryptPhrases(m,crypt.medpubkey)
    r2 = crypt.decryptPhrases(c2,crypt.medseckey)
    medend = datetime.datetime.now()
    crypt.totalTimes.append(medend - medstart)

    largestart = datetime.datetime.now()
    c4 = crypt.encryptPhrases(l,crypt.largepubkey)
    r4 = crypt.decryptPhrases(c4,crypt.largeseckey)
    largeend = datetime.datetime.now()
    crypt.totalTimes.append(largeend - largestart)

    sAvgE = crypt.calcAverage(crypt.converToSeconds(crypt.smallencryptTimes))
    sAvgD = crypt.calcAverage(crypt.converToSeconds(crypt.smalldecryptTimes))
    mAvgE = crypt.calcAverage(crypt.converToSeconds(crypt.medencrypttTimes))
    mAvgD = crypt.calcAverage(crypt.converToSeconds(crypt.meddecryptTimes))
    lAvgE = crypt.calcAverage(crypt.converToSeconds(crypt.largeencryptTimes))
    lAvgD = crypt.calcAverage(crypt.converToSeconds(crypt.largedecryptTimes))
    rsaEncryptionAverages[0] += sAvgE
    rsaEncryptionAverages[1] += mAvgE
    rsaEncryptionAverages[2] += lAvgE
    rsaDecryptionAverages[0] += sAvgD
    rsaDecryptionAverages[1] += mAvgD
    rsaDecryptionAverages[2] += lAvgD
    crypt.totalTimes = crypt.converToSeconds(crypt.totalTimes)
    for i in range(0,3):
        rsaTotals[i] += crypt.totalTimes[i]


def runModRSA(s,m,l):
    smallmod = modrsa()
    medmod = modrsa()
    largemod = modrsa()

    smallstart = datetime.datetime.now()
    smallmod.encryptDecryptPhrases(s)
    smallend = datetime.datetime.now()
    totalTime = smallend - smallstart
    totalTime = totalTime.seconds + (totalTime.microseconds/1000000)
    modRsaTotals[0] += totalTime
    smallmod.addTimes()
    smallavgE = smallmod.calcAverage(smallmod.encryptTimes)
    smallavgD = smallmod.calcAverage(smallmod.decryptTimes)
    modRsaEncryptionAverages[0] += smallavgE
    modRsaDecryptionAverages[0] += smallavgD

    medstart = datetime.datetime.now()
    medmod.encryptDecryptPhrases(m)
    medend = datetime.datetime.now()
    totalTime = medend - medstart
    totalTime = totalTime.seconds + (totalTime.microseconds/1000000)
    modRsaTotals[1] += totalTime
    medmod.addTimes()
    medavgE = medmod.calcAverage(medmod.encryptTimes)
    medavgD = medmod.calcAverage(medmod.decryptTimes)
    modRsaEncryptionAverages[1] += medavgE 
    modRsaDecryptionAverages[1] += medavgD

    largestart = datetime.datetime.now()
    largemod.encryptDecryptPhrases(l)
    largeend = datetime.datetime.now()
    totalTime = largeend - largestart
    totalTime = totalTime.seconds + (totalTime.microseconds/1000000)
    modRsaTotals[2] += totalTime
    largemod.addTimes()
    largeavgE = largemod.calcAverage(largemod.encryptTimes)
    largeavgD = largemod.calcAverage(largemod.decryptTimes)
    modRsaEncryptionAverages[2] += largeavgE
    modRsaDecryptionAverages[2] += largeavgD

def runModRSAFive(five):
    mod = modrsa()
    
    start = datetime.datetime.now()
    mod.encryptDecryptPhrases(five)
    end = datetime.datetime.now()
    totalTime = end - start
    totalTime = totalTime.seconds + (totalTime.microseconds/1000000)
    totalFiveTimes[1] += totalTime
    mod.addTimes()
    avgE = mod.calcAverage(mod.encryptTimes)
    avgD = mod.calcAverage(mod.decryptTimes)
    encryptionFiveTimes[1] += avgE
    decryptionFiveTimes[1] += avgD

def runModRSAThree(three):
    mod = modrsa()
    
    start = datetime.datetime.now()
    mod.encryptDecryptPhrases(three)
    end = datetime.datetime.now()
    totalTime = end - start
    totalTime = totalTime.seconds + (totalTime.microseconds/1000000)
    totalThreeTimes[1] += totalTime
    mod.addTimes()
    avgE = mod.calcAverage(mod.encryptTimes)
    avgD = mod.calcAverage(mod.decryptTimes)
    encryptionThreeTimes[1] += avgE
    decryptionThreeTimes[1] += avgD


aesEncryptionAverages = [0,0,0]
aesDecryptionAverages = [0,0,0]
aesTotals = [0,0,0]

rsaEncryptionAverages = [0,0,0]
rsaDecryptionAverages = [0,0,0]
rsaTotals = [0,0,0]

modRsaEncryptionAverages = [0,0,0]
modRsaDecryptionAverages = [0,0,0]
modRsaTotals = [0,0,0]

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
    print("Running RSA Encryption and Decryption")
    runRSA(small,med,large)
    print()
    print("Running Mod-RSA Encryption and Decryption")
    runModRSA(small,med,large)
    print()


# average everything
for i in range(0,3):
    aesEncryptionAverages[i] = format(aesEncryptionAverages[i]/10, '.12f')
    aesDecryptionAverages[i] = format(aesDecryptionAverages[i]/10, '.12f')
    aesTotals[i] = aesTotals[i]/10

    rsaEncryptionAverages[i] = rsaEncryptionAverages[i]/10
    rsaDecryptionAverages[i] = rsaDecryptionAverages[i]/10
    rsaTotals[i] = rsaTotals[i]/10
    
    modRsaEncryptionAverages[i] = modRsaEncryptionAverages[i]/10
    modRsaDecryptionAverages[i] = modRsaDecryptionAverages[i]/10
    modRsaTotals[i] = modRsaTotals[i]/10

print(aesEncryptionAverages,rsaEncryptionAverages, modRsaEncryptionAverages)
print(aesDecryptionAverages,rsaDecryptionAverages, modRsaDecryptionAverages)
print(aesTotals,rsaTotals,modRsaTotals)


# graphing
dfRSAE = pd.DataFrame({'x': [117,245,468], 'RSA-Encryption Times': [rsaEncryptionAverages[0],rsaEncryptionAverages[1],rsaEncryptionAverages[2]] })
dfRSAD = pd.DataFrame({'x': [117,245,468], 'RSA-Decryption Times': [rsaDecryptionAverages[0],rsaDecryptionAverages[1],rsaDecryptionAverages[2]] })
plt.plot('x','RSA-Encryption Times', data=dfRSAE, linestyle='-', marker='o',color='r')
plt.plot('x','RSA-Decryption Times', data=dfRSAD, linestyle='-', marker='o',color='b')

# legend
plt.legend(loc=2, ncol=2)
# labels
plt.title("RSA Encryption and Decryption Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()

dfAESE = pd.DataFrame({'x': [117,245,468], 'AES-Encryption Times': [aesEncryptionAverages[0],aesEncryptionAverages[1],aesEncryptionAverages[2]] })
dfAESD = pd.DataFrame({'x': [117,245,468], 'AES-Decryption Times': [aesDecryptionAverages[0],aesDecryptionAverages[1],aesDecryptionAverages[2]] })
plt.plot('x','AES-Encryption Times', data=dfAESE,linestyle = '-', marker = 'o', color='g')
plt.plot('x','AES-Decryption Times', data=dfAESD,linestyle = '-', marker = 'o', color='#BE08FF')

# legend
plt.legend(loc=4, ncol=1)
# labels
plt.title("AES Encryption and Decryption Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()

dfModRSAE = pd.DataFrame({'x': [117,245,468], 'MOD-RSA-Encryption Times': [modRsaEncryptionAverages[0],modRsaEncryptionAverages[1],modRsaEncryptionAverages[2]] })
dfModRSAD = pd.DataFrame({'x': [117,245,468], 'MOD-RSA-Decryption Times': [modRsaDecryptionAverages[0],modRsaDecryptionAverages[1],modRsaDecryptionAverages[2]] })
plt.plot('x','MOD-RSA-Encryption Times', data=dfModRSAE,linestyle = '-', marker = 'o', color='black')
plt.plot('x','MOD-RSA-Decryption Times', data=dfModRSAD,linestyle = '-', marker = 'o', color='#FFA10C')

# legend
plt.legend(loc=5, ncol=1)
# labels
plt.title("Mod-RSA Encryption and Decryption Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()

dfRSA = pd.DataFrame({'x': [117,245,468], 'RSA Runtime': [rsaTotals[0],rsaTotals[1],rsaTotals[2]] })
dfAES = pd.DataFrame({'x': [117,245,468], 'AES Runtime': [aesTotals[0],aesTotals[1],aesTotals[2]] })
dfModRSA = pd.DataFrame({'x': [117,245,468], 'Mod-RSA Runtime': [modRsaTotals[0],modRsaTotals[1],modRsaTotals[2]] })
plt.plot('x','RSA Runtime', data=dfRSA, linestyle='-', marker='o',color='#1E12FF')
plt.plot('x','AES Runtime',data=dfAES, linestyle='-',marker='o',color='#01FF34')
plt.plot('x','Mod-RSA Runtime',data=dfModRSA, linestyle='-',marker='o',color='#FF001A')

plt.legend(loc=2,ncol=2)
#labels 
plt.title("AES, RSA, and Mod-RSA Runtimes", loc='left',fontsize=12,fontweight=0,color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()


## AES and Mod-RSA comparison 
encryptionFiveTimes = [0,0]
decryptionFiveTimes = [0,0]
totalFiveTimes = [0,0]
encryptionThreeTimes = [0,0]
decryptionThreeTimes = [0,0]
totalThreeTimes = [0,0]

for i in range(1,11):
    print("Running test " + str(i))
    dw.writeFiveThousand()
    dw.writeThreeThousand()
    five = dr.readFile("../Data/fiveThousand.txt")
    three = dr.readFile("../Data/threeThousand.txt")

    print("Running AES Encryption and Decryption on 5000 and 3000-character length messages")
    runAESThree(three)
    runAESFive(five)
    print()
    print("Running Mod-RSA Encryption and Decryption on 5000 and 3000-character length messages")
    runModRSAFive(five)
    runModRSAThree(three)

# average everything
for i in range(0,2):
    encryptionThreeTimes[i] = encryptionThreeTimes[i]/10
    decryptionThreeTimes[i] = decryptionThreeTimes[i]/10
    totalThreeTimes[i] = totalThreeTimes[i]/10
    encryptionFiveTimes[i] = encryptionFiveTimes[i]/10
    decryptionFiveTimes[i] = decryptionFiveTimes[i]/10
    totalFiveTimes[i] = totalFiveTimes[i]/10

encryptionFiveTimes[0] = format(encryptionFiveTimes[0], '.12f')
decryptionFiveTimes[0] = format(decryptionFiveTimes[0], '.12f')
encryptionThreeTimes[0] = format(encryptionThreeTimes[0], '.12f')
decryptionThreeTimes[0] = format(decryptionThreeTimes[0], '.12f')

print(encryptionThreeTimes,encryptionFiveTimes)
print(decryptionThreeTimes,decryptionFiveTimes)
print(totalThreeTimes,totalFiveTimes)

dfsAE = pd.DataFrame({'x': [0,3000,5000],'Encryption Time for AES': [format(0,'.12f'),encryptionThreeTimes[0],encryptionFiveTimes[0]] })
dfsAD = pd.DataFrame({'x': [0,3000,5000], 'Decryption Time for AES': [format(0,'.12f'),decryptionThreeTimes[0],decryptionFiveTimes[0]] })
plt.plot('x','Encryption Time for AES', data=dfsAE, linestyle='-', marker='o',color='#1E12FF')
plt.plot('x','Decryption Time for AES',data=dfsAD, linestyle='-',marker='o',color='#01FF34')

# legend
plt.legend(loc=2, ncol=1)
# labels
plt.title("AES Encryption and Decryption Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()

dfsME = pd.DataFrame({'x': [0,3000,5000],'Encryption Time for Mod-RSA': [0,encryptionThreeTimes[1],encryptionFiveTimes[1]] })
dfsMD = pd.DataFrame({'x': [0,3000,5000],'Decryption Time for Mod-RSA': [0,decryptionThreeTimes[1],decryptionFiveTimes[1]] })
plt.plot('x','Encryption Time for Mod-RSA', data=dfsME, linestyle='-', marker='o',color='#1E12FF')
plt.plot('x','Decryption Time for Mod-RSA',data=dfsMD, linestyle='-',marker='o',color='#01FF34')

# legend
plt.legend(loc=2, ncol=1)
# labels
plt.title("Mod-RSA Encryption and Decryption Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()

dfsAT = pd.DataFrame({'x': [0,3000,5000],'Run Time for AES': [0,totalThreeTimes[0],totalFiveTimes[0]] })
dfsMT = pd.DataFrame({'x': [0,3000,5000],'Run Time for Mod-RSA': [0,totalThreeTimes[1],totalFiveTimes[1]] })
plt.plot('x','Run Time for AES', data=dfsAT, linestyle='-', marker='o',color='#1E12FF')
plt.plot('x','Run Time for Mod-RSA',data=dfsMT, linestyle='-',marker='o',color='#01FF34')

# legend
plt.legend(loc=2, ncol=1)
# labels
plt.title("AES and Mod-RSA Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()
