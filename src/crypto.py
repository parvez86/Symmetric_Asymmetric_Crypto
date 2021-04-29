import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
# from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA, SHA1, SHA256, SHA512, MD5
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii, time


def writeFile(filename, data):
    path = '../data/'
    with open(path+filename, 'w') as file:
        file.write(data)


def readFile(filename):
    path = '../data/'
    data = ''
    with open(path+filename, 'r') as file:
        data = json.loads(file.read())
    return data


def writeFileBytes(filename, data):
    path = '../data/'
    with open(path+filename, 'wb') as file:
        file.write(data)

def readFileBytes(filename):
    path = '../data/'
    data = ''
    with open(path+filename, 'rb') as file:
        data = file.read()

    return data


def writeOuput(data):
    with open('../data/output.txt', 'a') as f:
        f.write(data + '\n')


# AES Encryption - Decryption
class genAES:
    def __init__(self):
        while True:
            keyType = int(input('Enter the integer value of AES key type (1- 128bits , 2- 256bits): '))
            if keyType == 1 or keyType == 2:
                break
            print('Please, enter the valid input.')
        if keyType == 1:
            key = get_random_bytes(16)
        else:
            key = get_random_bytes(32)

        writeFileBytes('AES/AESKey.txt', key)
        f = open('../data/output.txt', 'w')
        f.close()

    # Encryption
    def encrypt(self):

        while True:
            methodType = int(input('Enter the integer value of AES encryption method type(1- ECB, 2-CFB): '))
            if methodType == 1 or methodType == 2:
                break
            print('Please enter the correct value.')
        data = readFile('input.txt')['text']
        key = readFileBytes('AES/AESKey.txt')
        iv = ''

        if methodType == 1:
            # ECB encryption
            cipher = AES.new(key, AES.MODE_ECB)
            ct_bytes = cipher.encrypt(pad(bytes(data, encoding='utf-8'), AES.block_size))
            ciphText = b64encode(ct_bytes).decode('utf-8')
        else:
            # CFB encryption
            cipher = AES.new(key, AES.MODE_CFB)
            ct_bytes = cipher.encrypt(bytes(data, encoding='utf-8'))
            iv = b64encode(cipher.iv).decode('utf-8')
            ciphText = b64encode(ct_bytes).decode('utf-8')

        result = json.dumps({'iv': iv, 'ciphertext': ciphText, 'methodType': methodType})
        writeFile('AES/AESCipherText.txt', result)
        print('The AES cipher text: %s (iv: %s)' % (ciphText, iv))
        writeOuput('The AES cipher text: %s (iv: %s)' % (ciphText, iv))

    # Decryption
    def decrypt(self):
        # load data
        data = readFile('AES/AESCipherText.txt')
        key = readFileBytes('AES/AESKey.txt')
        iv = data['iv']
        ciphText = data['ciphertext']
        methodType = data['methodType']
        plaintText = ''

        try:
            # For ECB
            if methodType == 1:
                plainText = unpad(AES.new(key, AES.MODE_ECB).decrypt(b64decode(ciphText)), AES.block_size).decode('utf-8')
            # For CFB
            else:
                plainText = AES.new(key, AES.MODE_CFB, b64decode(iv)).decrypt(b64decode(ciphText)).decode('utf-8')
        except (ValueError, KeyError) as e:
            print(e)
        writeFile('AES/AESPlainText.txt', json.dumps({'plaintext': plainText}))
        print('The AES plaintext: ', plainText)
        writeOuput('The AES plaintext: %s' % plainText)


# RSA Encryption - Decryption
class genRSA:
    def __init__(self, keysize=1024):
        self.sec_key = RSA.generate(keysize, Random.new().read)
        writeFileBytes('RSA/RSAPrivateKey.pem', self.sec_key.exportKey())
        writeFileBytes('RSA/RSAPublicKey.pem', self.sec_key.publickey().exportKey())

    # encryption
    def encrypt(self):
        text = readFile('input.txt')['text']
        pub_key = RSA.importKey(readFileBytes('RSA/RSAPublicKey.pem'))

        cipher = PKCS1_OAEP.new(pub_key)
        ciphText = b64encode(cipher.encrypt(bytes(text, encoding='utf-8')))
        writeFile('RSA/RSACipherText.txt', json.dumps({'ciphertext': ciphText.decode('utf-8')}))
        print('The RSA cipher text: ', b64decode(ciphText))
        writeOuput('The RSA cipher text: %s' % b64decode(ciphText))

    # decryption
    def decrypt(self):
        sec_key = RSA.importKey(readFileBytes('RSA/RSAPrivateKey.pem'))
        ciphText = readFile('RSA/RSACipherText.txt')['ciphertext']
        plainText = PKCS1_OAEP.new(sec_key).decrypt(b64decode(ciphText)).decode('utf-8')
        writeFile('RSA/RSAPlainText.txt', json.dumps({'plaintext': plainText}))
        print('The RSA plain text: ', plainText)
        writeOuput('The RSA plain text: %s' % plainText)

    # generate hash
    def getHash(self, hashAlgo='SHA-256'):
        text = bytes(readFile('input.txt')['text'], encoding='utf-8')
        if hashAlgo == 'SHA-512':
            hash = SHA512.new(text)
        elif hashAlgo == 'SHA-256':
            hash = SHA256.new(text)
        elif hashAlgo == 'SHA-1':
            hash = SHA1.new(text)
        elif hashAlgo == 'SHA':
            hash = SHA.new(text)
        else:
            hash = MD5.new(text)

        # return hash.digest()
        writeFileBytes('RSA/Hash.txt', binascii.hexlify(hash.digest()))

    # Generate signature
    def getSign(self, hashAlgo='SHA-256'):
        sec_key = RSA.importKey(readFileBytes('RSA/RSAPrivateKey.pem'))
        self.getHash(hashAlgo)
        hash = binascii.unhexlify(readFileBytes('RSA/Hash.txt'))
        signature = pow(int.from_bytes(hash, byteorder='big'), sec_key.d, sec_key.n)
        writeFile('RSA/Signature.txt', str(hex(signature)))

    # Verify Signature
    def verifySign(self, hashAlgo='SHA-256'):
        pubKey = RSA.importKey(readFileBytes('RSA/RSAPublicKey.pem'))

        try:
            signature = int(open('../data/RSA/Signature.txt', 'r').read(), 16)
            self.getHash()
            hash = int.from_bytes(binascii.unhexlify(readFileBytes('RSA/Hash.txt')), byteorder='big')
            hashFromSignature = pow(signature, pubKey.e, pubKey.n)

            if hash == hashFromSignature:
                print('Signature is valid.')
                writeOuput('Signature is valid.')
            else:
                print('Signature is invalid.')
                writeOuput('Signature is invalid.')
        except FileNotFoundError as e:
            print(e)


if __name__ == '__main__':
    aes = genAES()
    rsa = genRSA()

    screen = """
Enter the integer value of your chosen option:
    1 -> AES Encryption
    2 -> AES Decryption
    3 -> RSA Encryption
    4 -> RSA Decryption
    5 -> RSA Signature
    6 -> RSA Verification
    7 -> RSA Hash
"""

    while True:
        option = int(input(screen))
        if option == 1:
            writeOuput("AES encryption start!\n")
            aes.encrypt()
            writeOuput('\nAES decryption end!\n')
        elif option == 2:
            writeOuput('\nAES description start!\n')
            aes.decrypt()
            writeOuput('\nAES description end!\n')
        elif option == 3:
            writeOuput('\nRSA encryption start!\n')
            rsa.encrypt()
            writeOuput('\nRSA encryption end!\n')
        elif option == 4:
            writeOuput('\nRSA description start!\n')
            rsa.decrypt()
            writeOuput('\nRSA description end!\n')
        elif option == 5:
            writeOuput('\nGenerating signature start!\n')
            rsa.getSign()
            signature = open('../data/RSA/Signature.txt', 'r').read()
            print('Signature:', signature)
            writeOuput('Signature: %s' % signature)
            writeOuput('\nGenerating signature end!\n')
        elif option == 6:
            writeOuput('\nVerifying signature start!\n')
            rsa.verifySign()
            writeOuput('\nVerifying signature end!\n')
        elif option == 7:
            writeOuput('\nHashing start!\n')
            rsa.getHash()
            print('Hash:', readFileBytes('RSA/Hash.txt'))
            writeOuput('Hash: %s' % readFileBytes('RSA/Hash.txt'))
            writeOuput('\nHashing end!\n')
        else:
            print('System terminated...\n')
            writeOuput('System terminated...\n')
            break