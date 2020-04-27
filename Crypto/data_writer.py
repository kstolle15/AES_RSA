# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/21/2020
# This program will be used to create test data for the AES and RSA algorithms

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

def writeHundred():
    phrases = []
    phrases = getPhrases(100,phrases)
    try:
        f = open("../Data/hundred.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def writeThousand():
    phrases = []
    phrases = getPhrases(1000,phrases)
    try:
        f = open("../Data/thousand.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def writeTwoThousand():
    phrases = []
    phrases = getPhrases(2000,phrases)
    try:
        f = open("../Data/twoThousand.txt", "w")
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


writeFiveThousand()
