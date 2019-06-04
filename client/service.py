#!/usr/bin/env python3
import sys
import json

# Importing from parent directory
sys.path.append('..')
import database as db
import hashing_algorithms as ha

K_s = ha.hash('service_master_password').decode('utf-8')

ticket = db.load_database('service_ticket')

T_c_s = ticket['T_c_s']
message = ticket['message']

decrypted_T_c_s = ha.aes_decrypt(T_c_s['encrypted_message'], K_s, T_c_s['nonce'], T_c_s['tag'])

print('Decrypted: ')
print(decrypted_T_c_s)

