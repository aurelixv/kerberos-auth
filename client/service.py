#!/usr/bin/env python3
import sys
import json
from datetime import datetime

# Importing from parent directory
sys.path.append('..')
import database as db
import hashing_algorithms as ha

try:
    K_s = ha.hash('service_master_password').decode('utf-8')

    ticket = db.load_database('service_ticket')

    T_c_s = ticket['T_c_s']
    message = ticket['message']

    decrypted_T_c_s = ha.aes_decrypt(T_c_s['encrypted_message'], K_s, T_c_s['nonce'], T_c_s['tag'])
    decrypted_T_c_s = json.loads(decrypted_T_c_s)
    decrypted_message = ha.aes_decrypt(message['encrypted_message'], decrypted_T_c_s['K_c_s'], message['nonce'], message['tag'])
    decrypted_message = json.loads(decrypted_message)

    T_c_s_ID_C = decrypted_T_c_s['ID_C']
    message_ID_C = decrypted_message['ID_C']
    T_a = decrypted_T_c_s['T_A']
    T_a = datetime.strptime(T_a, '%Y-%m-%d %H:%M:%S.%f')
except IndentationError:
    print('Error reading the ticket.')
    sys.exit(1)

if T_c_s_ID_C == message_ID_C:
    print('Client authorized successfully.')
    if T_a >= datetime.now():
        print('Time remaining: ' + str(T_a - datetime.now()))
    else:
        print('Time expirated!')
else:
    print('Client not authorized!')
    sys.exit(1)

print('Decrypted T_c_s: ')
print(decrypted_T_c_s)
print('Decrypted message: ')
print(decrypted_message)

