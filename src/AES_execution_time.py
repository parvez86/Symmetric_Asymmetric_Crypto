from matplotlib import pyplot as plt
from src.crypto import *


class AESExecTime:
    def __init__(self, keysize):
        # generate & store key
        key = get_random_bytes(keysize)
        writeFileBytes('AES/AESKey.txt', key)

    def get_exec_time(self):
        # load data
        plaintext = readFile('../data/input.txt')['text']
        key = readFileBytes('../data/AES/AESKey.txt')

        # encryption
        cipher = AES.new(key, AES.MODE_ECB)
        ct_bytes = cipher.encrypt(pad(bytes(plaintext, encoding='utf-8'), AES.block_size))
        ciphText = b64encode(ct_bytes).decode('utf-8')
        writeFile('../data/AES/AESCipherText.txt', json.dumps({'ciphertext': ciphText}))

        # decryption
        ciphText = readFile('AES/AESCipherText.txt')['ciphertext']
        plainText = unpad(AES.new(key, AES.MODE_ECB).decrypt(b64decode(ciphText)), AES.block_size).decode('utf-8')
        writeFile('../data/AES/AESPlainText.txt', json.dumps({'plaintext': plainText}))


if __name__ == '__main__':
        key = ['128', '192', '256']
        key_size = [16, 24, 32]
        elapsedTime = list()
        for i in range(len(key)):
            startTime = time.time()
            aes = AESExecTime(key_size[i])
            aes.get_exec_time()
            endTime = time.time()
            # print(stime, etime)
            # time = AES.get_exec_time()
            elapsedTime.append(round((endTime-startTime), 4))
        print(elapsedTime)

        plt.bar(key, elapsedTime)
        plt.title('AES execution time')
        plt.ylabel('AES elapsed time (in seconds)')
        plt.xlabel('AES Key length (in bits)')
        plt.savefig('../data/graphs/AESExecTime.png')
        plt.show()
        plt.close()
