# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/26/2020
# This program will be used to encrypt and decrypt data using AES-CBC

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes as grb
import random
import datetime

class aes:
    def __init__(self, **kwargs):
        self.key = self.setKey()
        self.iv = self.setIV()
        self.encryptTimes = []
        self.decryptTimes = []
        self.totalTime = 0

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
    
    def getEncryptTimes(self):
        return self.encryptTimes

    def getDecryptTimes(self):
        return self.decryptTimes

    def getTotalTimes(self):
        return self.totalTimes

    def encrypt(self,plaintext):
        enc = AES.new(self.key,AES.MODE_CBC,self.iv)
        return enc.encrypt(plaintext)

    def decrypt(self,ciphertext):
        dec = AES.new(self.key,AES.MODE_CBC,self.iv)
        return dec.decrypt(ciphertext)
    
    def encryptPhrases(self,phrases):
        encryptedPhrases = []
        for phrase in phrases:
            plaintext = pad(phrase,16)
            start = datetime.datetime.now()
            ciphertext = self.encrypt(plaintext)
            end = datetime.datetime.now()
            self.encryptTimes.append(end-start)
            encryptedPhrases.append(ciphertext)

        return encryptedPhrases

    def decryptPhrases(self,phrases):
        decryptedPhrases = []
        for line in phrases:
            start = datetime.datetime.now()
            recoveredText = self.decrypt(line)
            end = datetime.datetime.now()
            self.decryptTimes.append(end - start)
            recoveredText = unpad(recoveredText,16)
            decryptedPhrases.append(recoveredText)

        return decryptedPhrases 

    def calcAverage(self,list):
        sum = 0
        for i in list:
            sum += i
        return sum/len(list)

    def checkEquality(self,plain,recovered):
        i = 0
        while i < len(plain):
            if(plain[i] != recovered[i]):
                print("Line: " + i + "Plain Text: " + plain[i] + ", Recovered Text: " + recovered[i])
                return False
            i = i + 1
        return True

    def converToSeconds(self,list):
        newList = []
        for i in list:
            if (i.seconds < 1):
                i = i.microseconds/1000000
            else: 
                i = i.seconds + (i.microseconds/1000000)

            newList.append(i)
        return newList

def runTest():
    import data_reader as dr
    crypt = aes()
    fiveThousand = dr.readFile("../Data/fiveThousand.txt")
    if(testNum(fiveThousand,crypt)):
        print("Encryption and Decryption Successful for 5000 Phrases.")
    

def testNum(phrases,c):
    # encrypting
    start = datetime.datetime.now()
    cipherPhrases = c.encryptPhrases(phrases)
    # decrypting
    recoveredPhrases = c.decryptPhrases(cipherPhrases)
    end = datetime.datetime.now()
    c.totalTime = end - start
    c.totalTime = c.totalTime.seconds + (c.totalTime.microseconds/1000000)
    # test for equality 
    if(c.checkEquality(phrases,recoveredPhrases)):
        print(phrases[3],cipherPhrases[3],recoveredPhrases[3])
        avgD = c.calcAverage(c.converToSeconds(c.decryptTimes))
        avgE = c.calcAverage(c.converToSeconds(c.encryptTimes))
        print("Average encryption time: " + str(avgE) + " seconds , Average decryption time: " + str(avgD)+ " seconds")
        print("Print total time: " + str(c.totalTime))
        return True
    else:
        print("Something went wrong")
        return False
    
runTest()


    



