from src.crypto import *
import matplotlib.pyplot as plt


class RSAExecTime:
    def __init__(self, keysize):
        # generate & store key
        key = RSA.generate(keysize, Random.new().read)
        writeFileBytes('RSA/RSAPrivateKey.pem', key.exportKey())
        writeFileBytes('RSA/RSAPublicKey.pem', key.publickey().exportKey())

    def get_exec_time(self):
        # load data
        text = readFile('input.txt')['text']
        sec_key = RSA.importKey(readFileBytes('RSA/RSAPrivateKey.pem'))
        pub_key = RSA.importKey(readFileBytes('RSA/RSAPublicKey.pem'))

        # encryption
        cipher = PKCS1_OAEP.new(pub_key)
        ciphText = b64encode(cipher.encrypt(bytes(text, encoding='utf-8')))
        writeFile('RSA/RSACipherText.txt', json.dumps({'ciphertext': ciphText.decode('utf-8')}))

        # decryption
        ciphText = readFile('RSA/RSACipherText.txt')['ciphertext']
        plainText = PKCS1_OAEP.new(sec_key).decrypt(b64decode(ciphText)).decode('utf-8')
        # writeFile('RSA/RSAPlainText.txt', json.dumps({'plaintext': plainText}))


if __name__ == '__main__':
    key = ['1024', '2048', '4096']
    key_size = [1024, 2048, 4096]
    elapsedTime = list()
    for i in range(len(key_size)):
        startTime = time.time()
        rsa = RSAExecTime(key_size[i])
        rsa.get_exec_time()
        endTime = time.time()
        elapsedTime.append(round((endTime - startTime), 2))
    print(elapsedTime)

    plt.bar(key, elapsedTime, color='r')
    plt.title('RSA execution time')
    plt.ylabel('RSA elapsed time (in seconds)')
    plt.xlabel('RSA Key length (in bits)')
    plt.savefig('../data/graphs/RSAExecTime.png')
    plt.show()
    plt.close()
