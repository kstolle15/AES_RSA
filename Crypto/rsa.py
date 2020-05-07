# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/27/2020
# This program will be used to encrypt and decrypt data using RSA

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
import datetime


class rsa:
    def __init__(self, **kwargs):
        self.smallpubkey = self.getPubKey1024()
        self.smallseckey = self.getSecretKey1024()
        self.medpubkey = self.getPubKey2048()
        self.medseckey = self.getSecretKey2048()
        self.largepubkey = self.getPubKey4096()
        self.largeseckey = self.getSecretKey4096()
        self.smallencryptTimes = []
        self.medencrypttTimes = []
        self.largeencryptTimes = []
        self.smalldecryptTimes = []
        self.meddecryptTimes = []
        self.largedecryptTimes = []
        self.totalTimes = []

    def getPubKey4096(self):
        pub_key = ""
        try:
            f = open("../Data/public_key_4096.pem", "r")
            pkstring = f.read()
            pub_key = RSA.importKey(pkstring)
        except:
            print("something went wrong getting the public key.")
        finally:
            f.close()
        return pub_key

    def getPubKey2048(self):
        pub_key = ""
        try:
            f = open("../Data/public_key_2048.pem", "r")
            pkstring = f.read()
            pub_key = RSA.importKey(pkstring)
        except:
            print("something went wrong getting the public key.")
        finally:
            f.close()
        return pub_key

    def getPubKey1024(self):
        pub_key = ""
        try:
            f = open("../Data/public_key_1024.pem", "r")
            pkstring = f.read()
            pub_key = RSA.importKey(pkstring)
        except:
            print("something went wrong getting the public key.")
        finally:
            f.close()
        return pub_key

    def getSecretKey4096(self):
        sec_key = ""
        try:
            f = open("../Data/private_key_4096.pem", "r")
            skstring = f.read()
            sec_key = RSA.importKey(skstring)
        except:
            print("something went wrong getting the public key.")
        finally:
            f.close()
        return sec_key

    def getSecretKey2048(self):
        sec_key = ""
        try:
            f = open("../Data/private_key_2048.pem", "r")
            skstring = f.read()
            sec_key = RSA.importKey(skstring)
        except:
            print("something went wrong getting the public key.")
        finally:
            f.close()
        return sec_key

    def getSecretKey1024(self):
        sec_key = ""
        try:
            f = open("../Data/private_key_1024.pem", "r")
            skstring = f.read()
            sec_key = RSA.importKey(skstring)
        except:
            print("something went wrong getting the public key.")
        finally:
            f.close()
        return sec_key

    def checkEquality(self,plain,recovered):
        i = 0
        while i < len(plain):
            if(plain[i] != recovered[i]):
                print("Line: " + i + "Plain Text: " +
                plain[i] + ", Recovered Text: " + recovered[i])
                return False
            i = i + 1
        return True

    def encryptPhrases(self,phrases,key):
        cipher = []
        e = PKCS1_OAEP.new(key)
        for line in phrases:
            start = datetime.datetime.now()
            ciphertext = e.encrypt(line)
            end = datetime.datetime.now()
            if(key == self.smallpubkey):
                self.smallencryptTimes.append(end - start)
            elif(key == self.medpubkey):
                self.medencrypttTimes.append(end - start)
            else:
                self.largeencryptTimes.append(end - start)
            cipher.append(ciphertext)
        return cipher

    def decryptPhrases(self,phrases,key):
        recover = []
        d = PKCS1_OAEP.new(key)
        for line in phrases:
            start = datetime.datetime.now()
            recoveredtext = d.decrypt(line)
            end = datetime.datetime.now()
            if(key == self.smallseckey):
                self.smalldecryptTimes.append(end - start)
            elif(key == self.medseckey):
                self.meddecryptTimes.append(end - start)
            else: 
                self.largedecryptTimes.append(end - start)
            recover.append(recoveredtext)

        return recover
    
    def converToSeconds(self,list):
        newList = []
        for i in list:
            if (i.seconds < 1):
                i = i.microseconds/1000000
            else: 
                i = i.seconds + (i.microseconds/1000000)

            newList.append(i)
        return newList

    def calcAverage(self,list):
        sum = 0
        for i in list:
            sum += i
        return sum/len(list)


def runTest():
    # basic encryption and decryption test
    runBasicTest()
    if(largerTest()):
        print("Encryption and Decryption Successful for 117,245, and 468 length messages")
    else:
        print("Encryption and Decryption Failed for 117,245, and 468 length messages")


def largerTest():
    import data_reader as dr
    one = dr.readFile("../Data/117.txt")
    two = dr.readFile("../Data/245.txt")
    four = dr.readFile("../Data/468.txt")

    crypt = rsa()
    smallStart = datetime.datetime.now()
    c1 = crypt.encryptPhrases(one,crypt.smallpubkey)
    r1 = crypt.decryptPhrases(c1,crypt.smallseckey)
    smallEnd = datetime.datetime.now()
    crypt.totalTimes.append(smallEnd - smallStart)

    medstart = datetime.datetime.now()
    c2 = crypt.encryptPhrases(two,crypt.medpubkey)
    r2 = crypt.decryptPhrases(c2,crypt.medseckey)
    medend = datetime.datetime.now()
    crypt.totalTimes.append(medend - medstart)

    largestart = datetime.datetime.now()
    c4 = crypt.encryptPhrases(four,crypt.largepubkey)
    r4 = crypt.decryptPhrases(c4,crypt.largeseckey)
    largeend = datetime.datetime.now()
    crypt.totalTimes.append(largeend - largestart)


    if(crypt.checkEquality(one, r1) and crypt.checkEquality(two, r2) and crypt.checkEquality(four, r4)):
        print(r1[3], one[3])
        print(r2[3], two[3])
        print(r4[3], four[3])
        sAvgE = crypt.calcAverage(crypt.converToSeconds(crypt.smallencryptTimes))
        sAvgD = crypt.calcAverage(crypt.converToSeconds(crypt.smalldecryptTimes))
        mAvgE = crypt.calcAverage(crypt.converToSeconds(crypt.medencrypttTimes))
        mAvgD = crypt.calcAverage(crypt.converToSeconds(crypt.meddecryptTimes))
        lAvgE = crypt.calcAverage(crypt.converToSeconds(crypt.largeencryptTimes))
        lAvgD = crypt.calcAverage(crypt.converToSeconds(crypt.largedecryptTimes))
        print("Average Small encryption time: " + str(sAvgE) + " seconds, average med encryption time: " + str(mAvgE) + " seconds, average large encryption time: " + str(lAvgE))
        print("Average Small decryption time: " + str(sAvgD) + " seconds, average med decryption time: " + str(mAvgD) + " seconds, average large decryption times: " + str(lAvgD))
        print(crypt.converToSeconds(crypt.totalTimes))
        return True
    else:
        return False


def runBasicTest():
    crypt = rsa()
    # testing encrypting a message
    message = b"Hello Kyle"
    e = PKCS1_OAEP.new(crypt.smallpubkey)
    d = PKCS1_OAEP.new(crypt.smallseckey)
    ciphertext = e.encrypt(message)
    # testing decrypting the message
    recoveredtext = d.decrypt(ciphertext)
    print(message)
    print(ciphertext)
    print(recoveredtext)