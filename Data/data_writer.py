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
        f = open("ten.txt", "w")
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
        f = open("hundred.txt", "w")
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
        f = open("thousand.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def writeHundredThousand():
    phrases = []
    phrases = getPhrases(100000,phrases)
    try:
        f = open("hundredThousand.txt", "w")
        for i in phrases:
            f.write(i)
            f.write("\n")
    except IOError:
        print("An error occured trying to write to the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()

def writeMillion():
    phrases = []
    phrases = getPhrases(1000000,phrases)
    try:
        f = open("million.txt", "w")
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


writeFirstTen()
writeHundred()
writeThousand()
