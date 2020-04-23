# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/23/2020
# This program will be used to read test data for the AES and RSA algorithms

def readFirstTen():
    phrases = []
    try:
        f = open("firstTen.txt", "r")
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            phrases.append(line)
    except IOError:
        print("An error occured trying to read the file,")
    except:
        print("A non file related error occured.")
    finally:
        f.close()
    
    return phrases
