# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/21/2020
# This program will be used to create test data for the AES and RSA algorithms
"""
NOTE: 
117 = max string length for encryption with 1024-bit RSA key
245 = max string length for encryption with 2048-bit RSA key
468 = max string length for encryption with 4096-bit RSA key

""" 

import os 
import string
import random 

alphabet = list(string.ascii_lowercase)

def writeFirstTen():
    phrases = []
    phrases = getPhrases(10,phrases)
    try:
        f = open("../Data/ten.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def write117bytes():
    phrases = []
    phrases = getPhrases(86,phrases) # 86 length strings are 117 bytes after encoding
    try:
        f = open("../Data/117.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def write245bytes():
    phrases = []
    phrases = getPhrases(214,phrases) # 214 length strings are 245 bytes after encoding
    try:
        f = open("../Data/245.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def write468bytes():
    phrases = []
    phrases = getPhrases(470,phrases) # 470 length strings are 468 bytes after encoding
    try:
        f = open("../Data/468.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def writeThreeThousand():
    phrases = []
    phrases = getPhrases(3000,phrases)
    try:
        f = open("../Data/threeThousand.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def writeFiveThousand():
    phrases = []
    phrases = getPhrases(5000,phrases)
    try:
        f = open("../Data/fiveThousand.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def getPhrases(num,phrases):
    for i in range(1,(num +1)):
        phrase = ""
        for j in range(1,i+1): 
            x = random.randint(1,(len(alphabet)-1))
            phrase += alphabet[x]
        phrases.append(phrase)

    return phrases


write117bytes()
write245bytes()
write468bytes()
#writeFiveThousand()
