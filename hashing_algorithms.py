import hashlib
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def hash(data, size = None):
    hashed_data = hashlib.sha512(data.encode('utf-8')).hexdigest()
    if size:
        return hashed_data[:size].encode('utf-8')
    return hashed_data.encode('utf-8')

def aes_encrypt(data, key):
    data = data.encode('utf-8')
    key = hash(key, 32)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    ciphertext, nonce, tag = (b64encode(x).decode('utf-8') for x in (ciphertext, nonce, tag))
    return ciphertext, nonce, tag

def aes_decrypt(data, key, nonce, tag):
    data, nonce, tag = (b64decode(x) for x in (data, nonce, tag))
    key = hash(key, 32)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt(data).decode('utf-8')
    try:
        cipher.verify(tag)
        return plaintext
    except:
        print('Erro na verificacao da criptografia.')
        return
