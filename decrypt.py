# Dencryption

import sys, math
 
SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'
 
def main():
     # Runs a test that encrypts a message to a file or decrypts a message
     # from a file.
     filename = 'encrypted_file.txt' # The file to write to/read from.
     privKeyFilename = 'RSA_privkey.txt'
     print('Reading from %s and decrypting...' % (filename))
     decryptedText = readFromFileAndDecrypt(filename, privKeyFilename)
     print('Decrypted text:')
     print(decryptedText)
     fo = open('decrypt.txt', 'w')
     fo.write(str(decryptedText))
     fo.close()
     print('The decrypted message is saved in the decrypt.txt')

def getTextFromBlocks(blockInts, messageLength, blockSize):
     # Converts a list of block integers to the original message string.
     # The original message length is needed to properly convert the last
     # block integer.
     message = []
     for blockInt in blockInts:
        blockMessage = []
        for i in range(blockSize - 1, -1, -1):
            if len(message) + i < messageLength:
                # Decode the message string for the 128 (or whatever
                # blockSize is set to) characters from this block integer:
                charIndex = blockInt // (len(SYMBOLS) ** i)
                blockInt = blockInt % (len(SYMBOLS) ** i)
                blockMessage.insert(0, SYMBOLS[charIndex])
        message.extend(blockMessage)
     return ''.join(message)

def decryptMessage(encryptedBlocks, messageLength, key, blockSize):
     # Decrypts a list of encrypted block ints into the original message
     # string. The original message length is required to properly decrypt
     # the last block. Be sure to pass the PRIVATE key to decrypt.
     decryptedBlocks = []
     n, d = key
     for block in encryptedBlocks:
         # plaintext = ciphertext ^ d mod n
         decryptedBlocks.append(pow(block, d, n))
     return getTextFromBlocks(decryptedBlocks, messageLength, blockSize)
 
def readKeyFile(keyFilename):
     # Given the filename of a file that contains a public or private key,
     # return the key as a (n,e) or (n,d) tuple value.
     fo = open(keyFilename)
     content = fo.read()
     fo.close()
     keySize, n, EorD = content.split(',')
     return (int(keySize), int(n), int(EorD))

def readFromFileAndDecrypt(messageFilename, keyFilename):
     # Using a key from a key file, read an encrypted message from a file
     # and then decrypt it. Returns the decrypted message string.
     keySize, n, d = readKeyFile(keyFilename)


     # Read in the message length and the encrypted message from the file:
     fo = open(messageFilename)
     content = fo.read()
     messageLength, blockSize, encryptedMessage = content.split('_')
     messageLength = int(messageLength)
     blockSize = int(blockSize)

     # Check that key size is large enough for the block size:
     if not (math.log(2 ** keySize, len(SYMBOLS)) >= blockSize):
         sys.exit('ERROR: Block size is too large for the key and symbol set size. Did you specify the correct key file and encrypted file?')

     # Convert the encrypted message in to large int values:
     encryptedBlocks = []
     for block in encryptedMessage.split(','):
         encryptedBlocks.append(int(block))
     # Decrypt the large int values:
     return decryptMessage(encryptedBlocks, messageLength, (n, d),blockSize)


#If publicKeyCipher.py is run (instead of imported as a module), call
# the main() function.
if __name__ == '__main__':
     main()

