#!/usr/bin/env python3
import sys
import os
import socket
import selectors
import json
from datetime import datetime, timedelta

# Importing from parent directory
sys.path.append('..')
import database as db
import hashing_algorithms as ha

HOST = '127.0.0.1'
PORT = 60002

sel = selectors.DefaultSelector()

print('Starting TGS server at ' + HOST + ' port ' + str(PORT))

TGS_db = db.load_database('TGS_db')

# Adds a new service via CLI params (add [service_name] [key])
try:
    if sys.argv[1] == 'add':
        service_name = str(sys.argv[2])
        key = ha.hash(str(sys.argv[3])).decode('utf-8')
        print('Adding service - name: ' + service_name + ' key: ' + key[:4] + '***' + key[len(key) - 4:])
        db.insert(TGS_db, service_name, key)
        db.save_database('TGS_db', TGS_db)
except IndexError:
    print('No new service added.')

def accept(sock, mask):

    os.system('clear')

    conn, addr = sock.accept()
    print('Client connected ' + str(addr))
    conn.setblocking(False)    
    conn.sendall(b'--- Welcome to the TGS Server. ---')
    sel.register(conn, selectors.EVENT_READ, worker)

def worker(conn, mask):
    data = conn.recv(1024)
    if data:
        request = json.loads(data.decode('utf-8'))
        print('------------------------------------------')
        print(str(conn.getpeername()) + ' sent M3: ' + str(request))

        T_c_tgs = request['T_c_tgs']
        message = request['message']

        decrypted_T_c_tgs = ha.aes_decrypt(
            T_c_tgs['encrypted_message'], 
            TGS_db['TGS'], 
            T_c_tgs['nonce'], 
            T_c_tgs['tag']
        )
        decrypted_T_c_tgs = json.loads(decrypted_T_c_tgs)

        print('------------------------------------------')
        print('Decrypted TGS ticket from the AS server: ')
        print(decrypted_T_c_tgs)


        decrypted_message = ha.aes_decrypt(
            message['encrypted_message'],
            decrypted_T_c_tgs['K_c_tgs'],
            message['nonce'],
            message['tag']
        )
        decrypted_message = json.loads(decrypted_message)

        print('------------------------------------------')
        print('Decrypted message from client with the AS token key: ')
        print(decrypted_message)

        if decrypted_message['ID_S'] in TGS_db:

            if decrypted_T_c_tgs['ID_C'] != decrypted_message['ID_C'] or decrypted_T_c_tgs['T_R'] != decrypted_message['T_R']:
                print('Error validating data.')
                conn.sendall(b'Error validating data.')
                return

            K_c_s = ha.random()

            T_a = datetime.now() + timedelta(0, decrypted_T_c_tgs['T_R'])

            response = {
                'K_c_s': K_c_s,
                'T_A': str(T_a),
                'N2': decrypted_message['N2']
            }

            print('------------------------------------------')
            print('Response:')
            print(response)
            print('------------------------------------------')
            print('K_c_tgs:')
            print(decrypted_T_c_tgs['K_c_tgs'])

            encrypted_message, nonce, tag = ha.aes_encrypt(json.dumps(response), decrypted_T_c_tgs['K_c_tgs'])
            response = {
                'encrypted_message': encrypted_message,
                'nonce': nonce,
                'tag': tag
            }

            T_c_s = {
                'ID_C': decrypted_T_c_tgs['ID_C'],
                'T_A': str(T_a),
                'K_c_s': K_c_s
            }

            print('------------------------------------------')
            print('T_c_s:')
            print(T_c_s)
            print('------------------------------------------')
            print('K_s:')
            print(TGS_db[decrypted_message['ID_S']])

            encrypted_message, nonce, tag = ha.aes_encrypt(json.dumps(T_c_s), TGS_db[decrypted_message['ID_S']])
            T_c_s = {
                'encrypted_message': encrypted_message,
                'nonce': nonce,
                'tag': tag
            }

            print('------------------------------------------')
            print('Sending M4 to client...')
            print('Response: ' + str(response))
            print('T_c_s: ' + str(T_c_s))
            print('------------------------------------------')

            conn.sendall(json.dumps({'response': response, 'T_c_s': T_c_s}).encode('utf-8'))
        else:
            conn.sendall(b'Unknown service.')

    else:
        print('Ending client ' + str(conn.getpeername()) + ' connection...')
        sel.unregister(conn)
        conn.close()

socket =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind((HOST, PORT))
socket.listen()
socket.setblocking(False)
print('Waiting clients...')
sel.register(socket, selectors.EVENT_READ, accept)

while True:
    events = sel.select()
    for key, mask in events:
        callback = key.data
        callback(key.fileobj, mask)
