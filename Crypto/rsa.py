# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/27/2020
# This program will be used to encrypt and decrypt data using RSA

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def getPubKey4096():
    pub_key = ""
    try:
        f = open("../Data/public_key_4096.pem","r")
        pkstring = f.read()
        pub_key = RSA.importKey(pkstring)
    except:
        print("something went wrong getting the public key.")
    finally:
        f.close()
    return pub_key

def getPubKey2048():
    pub_key = ""
    try:
        f = open("../Data/public_key_2048.pem","r")
        pkstring = f.read()
        pub_key = RSA.importKey(pkstring)
    except:
        print("something went wrong getting the public key.")
    finally:
        f.close()
    return pub_key

def getPubKey1024():
    pub_key = ""
    try:
        f = open("../Data/public_key_1024.pem","r")
        pkstring = f.read()
        pub_key = RSA.importKey(pkstring)
    except:
        print("something went wrong getting the public key.")
    finally:
        f.close()
    return pub_key

def getSecretKey4096():
    sec_key = ""
    try:
        f = open("../Data/private_key_4096.pem","r")
        skstring = f.read()
        sec_key = RSA.importKey(skstring)
    except:
        print("something went wrong getting the public key.")
    finally:
        f.close()
    return sec_key

def getSecretKey2048():
    sec_key = ""
    try:
        f = open("../Data/private_key_2048.pem","r")
        skstring = f.read()
        sec_key = RSA.importKey(skstring)
    except:
        print("something went wrong getting the public key.")
    finally:
        f.close()
    return sec_key

def getSecretKey1024():
    sec_key = ""
    try:
        f = open("../Data/private_key_1024.pem","r")
        skstring = f.read()
        sec_key = RSA.importKey(skstring)
    except:
        print("something went wrong getting the public key.")
    finally:
        f.close()
    return sec_key

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
    
    pkOne = getPubKey1024()
    skOne = getSecretKey1024()
    pkTwo = getPubKey2048()
    skTwo = getSecretKey2048()
    pkFour = getPubKey4096()
    skFour = getSecretKey4096()
    
    c1 = encryptPhrases(one,pkOne)
    c2 = encryptPhrases(two,pkTwo)
    c4 = encryptPhrases(four,pkFour)

    r1 = decryptPhrases(one,skOne)
    r2 = decryptPhrases(two,skTwo)
    r4 = decryptPhrases(four,skFour)

    if(checkEquality(one,r1) and checkEquality(two,r2) and checkEquality(four,r4)):
        return True
    else:
        return False

def checkEquality(plain,recovered):
    i = 0
    while i < len(plain):
        if(plain[i] != recovered[i]):
            print("Line: " + i + "Plain Text: " + plain[i] + ", Recovered Text: " + recovered[i])
            return False
        i = i + 1
    return True

def encryptPhrases(phrases,key):
    cipher = []
    e = PKCS1_OAEP.new(key)
    for line in phrases:
        ciphertext = e.encrypt(line.encode(encoding="UTF-8",errors='strict'))
        cipher.append(ciphertext)
    return cipher

def decryptPhrases(phrases,key):
    recover = []
    d = PKCS1_OAEP.new(key)
    for line in phrases:
        recoveredtext = d.decrypt(line)
        recoveredtext = recoveredtext.decode(encoding='UTF-8',errors='strict')
        recover.append(recoveredtext)
    return recover

def runBasicTest():
    pkey4 = getPubKey4096()
    skey4 = getSecretKey4096()
    pkey2 = getPubKey2048()
    skey2 = getSecretKey2048()
    pkey1 = getPubKey1024()
    skey1 = getSecretKey1024()
    # testing encrypting a message 
    message = "Hello Kyle"
    e = PKCS1_OAEP.new(pkey1)
    d = PKCS1_OAEP.new(skey1)
    ciphertext = e.encrypt(message.encode(encoding='UTF-8',errors='strict'))
    #testing decrypting the message
    recoveredtext = d.decrypt(ciphertext)
    recoveredtext = recoveredtext.decode(encoding='UTF-8',errors='strict')
    print(message)
    print(ciphertext)
    print(recoveredtext)


runTest()