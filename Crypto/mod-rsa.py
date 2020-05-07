# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/27/2020
# This program will be used to encrypt and decrypt data using RSA

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from AES import aes
import sys
import datetime

class modrsa:
    def __init__(self,**kwargs):
        self.crypt = aes()
        self.pubkey = self.getPubKey1024()
        self.seckey = self.getSecretKey1024()
        self.encryptTimes = []
        self.decryptTimes = []
        self.totalTime = 0
    
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
            self.encryptTimes.append(end - start)
            cipher.append(ciphertext)
        return cipher

    def decryptPhrases(self,phrases,key):
        recover = []
        d = PKCS1_OAEP.new(key)
        for line in phrases:
            start = datetime.datetime.now()
            recoveredtext = d.decrypt(line)
            end = datetime.datetime.now()
            self.decryptTimes.append(end - start)
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


def test():
    import data_reader as dr
    crypt 
    smallmod = modrsa()
    medmod = modrsa()
    largemod = modrsa()
    # reading files 
    one = dr.readFile("../Data/117.txt")
    two = dr.readFile("../Data/245.txt")
    four = dr.readFile("../Data/468.txt")

    

