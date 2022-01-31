#
#  Your assignment
#   By: Elita Danilyuk

import base64
import hashlib
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# define a class structure to define encrypt/decrypt methods

class AESCipher(object):

    # initialize the class instance and creating a key from user's password
    def __init__(self, passPhrase): 
        self.bs = AES.block_size
        print ("block size", self.bs)
        # get a 256 bit key by hashing your password
        self.key = hashlib.sha256(passPhrase.encode()).digest()
        print ("256 bit key derived from password:\n", self.key)
        print ()

    # method to perform AES encryption
    def encrypt(self, plainText):
        # the plaintext length must be a multiple of blocksize
        # Pad the data if necessary
        padded = self._pad(plainText) 
        # Each time we encrypt we will need a random initialization vector
        iv = Random.new().read(AES.block_size)
        # Instantiate a cipher object from the AES library
        # Give it the key, set it to cipher-block-chaining mode, and
        # give it the initialization vector
        cipherObject = AES.new(self.key, AES.MODE_CBC, iv)
        # Encrypt the data/padding after converting to byte array
        encrypted = cipherObject.encrypt(padded.encode('utf-8'))
        # concatenate the iv and the ciphertext and convert to base64                                 
        encoded = base64.b64encode(iv + encrypted)
        return encoded

    # method to perform AES decryption
    def decrypt(self, cipherText):
        # decode the base64 string which contains the IV and ciphertext
        encrypted = base64.b64decode(cipherText) 
        # strip off the initialization vector
        iv = encrypted[:AES.block_size]
        # instantiate an AES cipher object with same parameters as before
        cipherObject = AES.new(self.key, AES.MODE_CBC, iv)
        # decrypt the string, strip off the padding and return the plaintext
        return self._unpad(cipherObject.decrypt(encrypted[AES.block_size:]))

    # method to pad a string to an even multiple of block size
    # the pad character is a hex digit indicating the length of the padding
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    # method to strip the padding
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
    
#
#  The main routine
#

# read the ciphertext file as one block of data 

#### insert your code here

# opens and reads the base64 encoded ciphertext file
# decrypts this back into plaintext and prints it out

with open("lab2Plain.txt", "r") as fd:
    plaintext = fd.read()

passPhrase = "Hello Kitty!"
myCipher = AESCipher(passPhrase)
cipherText = myCipher.encrypt(plaintext)

# decrypt the file
plainText = myCipher.decrypt(cipherText)
print ("The plaintext:\n", plainText)