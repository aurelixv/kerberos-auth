# In[]
import hashing_algorithms as ha

# In[]
ciphertext, nonce, tag = ha.aes_encrypt('teste', 'key')
print(ciphertext,nonce,tag)

# In[]
ha.aes_decrypt(ciphertext, 'key', nonce, tag)
