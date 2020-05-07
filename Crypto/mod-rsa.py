# Kyle Stolle - CSCE 463 Final Project: AES vs RSA 04/27/2020
# This program will be used to encrypt and decrypt data using RSA

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import sys
import datetime