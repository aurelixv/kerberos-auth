#!/usr/bin/env python3
import sys
import os
import socket
import selectors
import json
from time import sleep

# Importing from parent directory
sys.path.append('..')
import database as db
import hashing_algorithms as ha

HOST = '127.0.0.1'
PORT = 60001

sel = selectors.DefaultSelector()

print('Starting AS server at ' + HOST + ' port ' + str(PORT))

AS_db = db.load_database('AS_db')

# Adds a new client via CLI params (add [name] [password])
try:
    if sys.argv[1] == 'add':
        name = str(sys.argv[2])
        password = ha.hash(str(sys.argv[3])).decode('utf-8')
        print('Adding client - name: ' + name + ' password: ' + password[:4] + '***' + password[len(password) - 4:])
        db.insert(AS_db, name, password)
        db.save_database('AS_db', AS_db)
except IndexError:
    print('No new clients added.')

def accept(sock, mask):
    conn, addr = sock.accept()
    print('Client connected ' + str(addr))
    conn.setblocking(False)    
    conn.sendall(b'--- Welcome to the AS Server. ---')
    sel.register(conn, selectors.EVENT_READ, worker)

def worker(conn, mask):
    data = conn.recv(1024)
    if data:
        request = json.loads(data.decode('utf-8'))
        print('------------------------------------------')
        print(str(conn.getpeername()) + ' sent: ' + str(request))
        print('------------------------------------------')
        message = request['message']

        if request['action'] == 'auth' and request['ID_C'] in AS_db:

            decrypted = ha.aes_decrypt(message['encrypted_message'], 
                AS_db[request['ID_C']], 
                message['nonce'], 
                message['tag']
            )

            if decrypted:
                decrypted = json.loads(decrypted)

                K_c_tgs = ha.random()

                response = {}
                response['K_c_tgs'] = K_c_tgs
                response['N1'] = decrypted['N1']
                encrypted_response, nonce, tag = ha.aes_encrypt(json.dumps(response), AS_db[request['ID_C']])
                response = {
                    'encrypted_message': encrypted_response,
                    'nonce': nonce,
                    'tag': tag
                }

                T_c_tgs = {}
                T_c_tgs['ID_C'] = request['ID_C']
                T_c_tgs['T_R'] = decrypted['T_R']
                T_c_tgs['K_c_tgs'] = K_c_tgs
                encrypted_T_c_tgs, nonce, tag = ha.aes_encrypt(json.dumps(T_c_tgs), AS_db['TGS'])
                T_c_tgs = {
                    'encrypted_message': encrypted_T_c_tgs,
                    'nonce': nonce,
                    'tag': tag
                }
                print('------------------------------------------')
                print('K_c_tgs: ' + str(K_c_tgs))
                print('------------------------------------------')
                print('------------------------------------------')
                print('Sending to client...')
                print('Response: ' + str(response))
                print('T_c_tgs: ' + str(T_c_tgs))
                print('------------------------------------------')

                conn.sendall(json.dumps({'response': response, 'T_c_tgs': T_c_tgs}).encode('utf-8'))
            else:
                conn.sendall(b'Error validating encrypted message.')

            #print(decrypted)

        else:
            conn.sendall(b'Unknown method/client.')

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
