# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/28/2020
# This program will be used to run both algorithms while recording runtimes and then displaying the results.

from AES import aes 
import rsa
import data_reader as dr 
import data_writer as dw 
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import datetime
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def runAES(s,m,l):
    small = aes()
    med = aes()
    large = aes()

    


# graphing
dfRSA = pd.DataFrame({'x': [117,245,468], 'RSA': [rsaAverages[0],rsaAverages[1],rsaAverages[2]] })
dfAES = pd.DataFrame({'x': [117,245,468], 'AES': [aesAverages[0],aesAverages[1],aesAverages[2]] })
dfModRSA = pd.DataFrame({'x': [117,245,468], 'MOD-RSA': [modrsaAverages[0],modrsaAverages[1],modrsaAverages[2]] })
plt.plot('x','RSA', data=dfRSA, linestyle='-', marker='o',color='r')
plt.plot('x','AES', data=dfAES,linestyle = '-', marker = 'o', color='g')
plt.plot('x','MOD-RSA', data=dfModRSA,linestyle = '-', marker = 'o', color='black')

print(dfAES)
print(dfModRSA)
print(dfRSA)

# legend
plt.legend(loc=2, ncol=2)
# labels
plt.title("AES and RSA Runtimes", loc='left', fontsize=12, fontweight=0, color='orange')
plt.xlabel("Length of Message (bytes)")
plt.ylabel("Time (Seconds)")
plt.show()
