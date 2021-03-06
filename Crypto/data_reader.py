# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/23/2020
# This program will be used to read test data for the AES and RSA algorithms

def readFile(file):
    phrases = []
    try:
        f = open(file, "r")
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            byte = bytes(line,'utf-8')
            phrases.append(byte)
    except IOError:
        print("An error occured trying to read the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()
    
    return phrases
