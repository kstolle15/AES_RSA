# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/27/2020
# This program will be used to encrypt and decrypt data using RSA

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
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
        self.ciphers = []
        self.recovered = []
    
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

    def encryptDecryptPhrases(self,phrases):
        e = PKCS1_OAEP.new(self.pubkey)
        d = PKCS1_OAEP.new(self.seckey)
        for line in phrases:
            # encrypt 
            plaintext = pad(line,16)
            start = datetime.datetime.now()
            ciphertext = self.crypt.encrypt(plaintext)
            end = datetime.datetime.now()
            self.crypt.encryptTimes.append(end - start)
            self.ciphers.append(ciphertext)
            
            modstart = datetime.datetime.now()
            self.crypt.key = e.encrypt(self.crypt.key)
            modend = datetime.datetime.now()
            self.encryptTimes.append(modend - modstart)

            # decrypt 
            decstart = datetime.datetime.now()
            self.crypt.key = d.decrypt(self.crypt.key)
            decend = datetime.datetime.now()
            self.decryptTimes.append(decend - decstart)

            start = datetime.datetime.now()
            recoveredText = self.crypt.decrypt(ciphertext)
            end = datetime.datetime.now()
            self.crypt.decryptTimes.append(end - start)
            recoveredText = unpad(recoveredText,16)
            self.recovered.append(recoveredText)

    
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

    def addTimes(self):
        # convert encryption times 
        self.crypt.encryptTimes = self.converToSeconds(self.crypt.encryptTimes)
        self.encryptTimes = self.converToSeconds(self.encryptTimes)
        # add them together
        i = 0
        while i < len(self.encryptTimes):
            self.encryptTimes[i] = self.encryptTimes[i] + self.crypt.encryptTimes[i]
            i += 1
        # convert decryption times 
        self.crypt.decryptTimes = self.converToSeconds(self.crypt.decryptTimes)
        self.decryptTimes = self.converToSeconds(self.decryptTimes)
        i = 0
        while i < len(self.decryptTimes):
            self.decryptTimes[i] = self.decryptTimes[i] + self.crypt.decryptTimes[i]
            i += 1
        

def test():
    import data_reader as dr
    smallmod = modrsa()
    medmod = modrsa()
    largemod = modrsa()
    # reading files 
    one = dr.readFile("../Data/117.txt")
    two = dr.readFile("../Data/245.txt")
    four = dr.readFile("../Data/468.txt")
    totalTimes = []

    smallstart = datetime.datetime.now()
    smallmod.encryptDecryptPhrases(one)
    smallend = datetime.datetime.now()
    totalTimes.append(smallend - smallstart)

    medstart = datetime.datetime.now()
    medmod.encryptDecryptPhrases(two)
    medend = datetime.datetime.now()
    totalTimes.append(medend - medstart)

    largestart = datetime.datetime.now()
    largemod.encryptDecryptPhrases(four)
    largeend = datetime.datetime.now()
    totalTimes.append(largeend - largestart)

    if(smallmod.checkEquality(one,smallmod.recovered)):
        print("Mod-rsa correctly worked for 117-byte messages")
        smallmod.addTimes()
        avgE = smallmod.calcAverage(smallmod.encryptTimes)
        avgD = smallmod.calcAverage(smallmod.encryptTimes)
        print("Average encryption time: " + str(avgE) + " seconds")
        print("Average decryption time: " + str(avgD) + " seconds")
        print()
    else:
        print("Mod-rsa failed for 117-byte messages")
        print()
    
    if(medmod.checkEquality(two,medmod.recovered)):
        print("Mod-rsa correctly worked for 245-byte messages")
        medmod.addTimes()
        avgE = medmod.calcAverage(medmod.encryptTimes)
        avgD = medmod.calcAverage(medmod.decryptTimes)
        print("Average encryption time: " + str(avgE) + " seconds")
        print("Average decryption time: " + str(avgD) + " seconds")
        print()
    else:
        print("Mod-rsa failed for 245-byte messages")
        print()

    if(largemod.checkEquality(four,largemod.recovered)):
        print("Mod-rsa correctly worked for 468-byte messages")
        largemod.addTimes()
        avgE = largemod.calcAverage(largemod.encryptTimes)
        avgD = largemod.calcAverage(largemod.decryptTimes)
        print("Average encryption time: " + str(avgE) + " seconds")
        print("Average decryption time: " + str(avgD) + " seconds")
        print()
    else:
        print("Mod-rsa failed for 245-byte messages")
        print()

    print("Total time taken to encrypt and decrypt messages")
    print(smallmod.converToSeconds(totalTimes))


