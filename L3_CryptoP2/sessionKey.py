# By: Elita Danilyuk

from Crypto.Hash import SHA256
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
import random

hash = "SHA-256"


def newkeys(keysize):
   random_generator = Random.new().read
   key = RSA.generate(keysize, random_generator)
   private, public = key, key.publickey()
   return public, private


def importKey(externKey):
   return RSA.importKey(externKey)


def getpublickey(priv_key):
   return priv_key.publickey()


def encrypt(message, pub_key):
   cipher = PKCS1_OAEP.new(pub_key)
   return cipher.encrypt(message)


def decrypt(ciphertext, priv_key):
   cipher = PKCS1_OAEP.new(priv_key)
   return cipher.decrypt(ciphertext)


def sign(message, priv_key, hashAlg="SHA-256"):
   global hash
   hash = hashAlg
   signer = PKCS1_v1_5.new(priv_key)

   if (hash == "SHA-512"):
      digest = SHA512.new()
   elif (hash == "SHA-384"):
      digest = SHA384.new()
   elif (hash == "SHA-256"):
      digest = SHA256.new()
   elif (hash == "SHA-1"):
      digest = SHA.new()
   else:
      digest = MD5.new()
   digest.update(message)
   return signer.sign(digest)


def verify(message, signature, pub_key):
   signer = PKCS1_v1_5.new(pub_key)
   if (hash == "SHA-512"):
      digest = SHA512.new()
   elif (hash == "SHA-384"):
      digest = SHA384.new()
   elif (hash == "SHA-256"):
      digest = SHA256.new()
   elif (hash == "SHA-1"):
      digest = SHA.new()
   else:
      digest = MD5.new()
   digest.update(message)
   return signer.verify(digest, signature)


BS = 16
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s): return s[0:-ord(s[-1])]


class AESCipher(object):

    # initialize the class instance and creating a key from user's password
    def __init__(self, passPhrase):
        self.bs = AES.block_size
        # get a 256 bit key by hashing your password
        self.key = hashlib.sha256(passPhrase.encode()).digest()
        print()

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
#    The rest is up to you....  make sure to print out appropriate values as necessary
#
#### DONE: Generate keypairs for Bob and Alice
Alice_publicKey, Alice_privateKey = newkeys(2048)
Bob_publicKey, Bob_privateKey = newkeys(2048)
print("Generated keypairs:\n\tAlice's public key:", repr(Alice_privateKey))
print("\tAlice's private key location: ", Alice_privateKey)
print("\tBob's public key:", repr(Bob_publicKey))
print("\tBob's private key location: ", Bob_privateKey)


#Alice tasks
#### DONE: Hash a pass phrase to create a 256 bit (32 byte) session key
#### DONE: Generate a public and private keypair
#### DONE: encrypt the session key with Bob's public key, convert to base64 and send the encoded, encrypted key to Bob
#### DONE: EXTRA CREDIT:  Use AES and the session key to encrypt a long message to Bob

# DONE: hash pass phrase
key = b"Guess What!"
msg = "Bob I heard Eve was spreading lies to make us split. Please come back, I miss you. I encrypted this message with the help of Elita Danilyuk (an amazing cybersecurity engineer) so Eve can't read it. Meet where we met for our first date. Tonight: 8:00PM"
session_key = SHA256.new()
session_key.update(key)
print("\nHashing the pass phrase to create a 256-bit session key:\n\talgorithm: ",
      hash, "\n\tsession key: ", session_key.digest())

# DONE: key pairs created above

print("\nEncrypting the session key with Bob's public key and converting it to base64:")

# DONE: encrypting session key with Bob's public key
encrypted_key = encrypt(session_key.digest(), Bob_publicKey)
print("\tencrypted key:", encrypted_key)
print("\t\tlength of encrypted key:", len(encrypted_key))

# DONE: convert to base64
encoded_encrypted_key = b64encode(encrypted_key)
print("\tbase64 version of encrypted key:", encoded_encrypted_key)
print("\t\tlength of base64 version:", len(encoded_encrypted_key))

# note: The message should give a good "soap opera" ending to our story of love and encryption
#### DONE: EXTRA CREDIT:  Use AES and the session key to encrypt a long message to Bob
myCipher = AESCipher(key.decode('UTF-8'))
encrypted_msg = myCipher.encrypt(msg)
print("EXTRA CREDIT: Using AES and the session key to encrypt a message to Bob:\n\tEncrypted message: ", encrypted_msg)


#### DONE: EXTRA CREDIT:  Create a digital signature for the AES-encrypted file
#### note: "send the file to Bob" (basically do nothing, the info will be stored in program variables.
signature = sign(encrypted_msg, Alice_privateKey)
print("\nEXTRA CREDIT: Creating a digital signature for AES-encrypted file:\n\tThis is the",
      len(signature), "bit digital signature signed by Alice: ", signature)
encoded_signature = b64encode(signature)
print("\tThis is the base64 version of the signature that would be sent in an email: ", encoded_signature)


#Bob tasks
#### DONE: EXTRA CREDIT:  verify the message is intact and came from Alice
#### DONE: decrypt the session key and decode it from base64
#### DONE: EXTRA CREDIT: use the session key to decrypt Alice's message

#### DONE: EXTRA CREDIT:  verify the message is intact and came from Alice
# encrypted_msg = b"updating the message to test a 'false' verification"
verification = verify(encrypted_msg, b64decode(
    encoded_signature), Alice_publicKey)
print("\nEXTRA CREDIT: verifying message is intact and from Alice:\n\tThe verification proved to be:", verification)

# DONE: decrypted and decoded session key
print("\nDecrypting the session key and decoding it from base64:")
decoded_encrypted_key = b64decode(encoded_encrypted_key)
decrypted_key = decrypt(decoded_encrypted_key, Bob_privateKey)
print("\tAlice's decrypted session key: ", decrypted_key)
print("\tDecoded from base64: ", decoded_encrypted_key)
print("\t\tlength of decoded session key: ", len(decoded_encrypted_key))

#### DONE: EXTRA CREDIT: use the session key to decrypt Alice's message
msg = myCipher.decrypt(encrypted_msg)
print("\nEXTRA CREDIT: decrypting Alice's message with the session key:\n\tThe plaintext message: ", msg)