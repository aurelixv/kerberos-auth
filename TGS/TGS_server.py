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
        print(str(conn.getpeername()) + ' sent: ' + str(request))
        print('------------------------------------------')

        T_c_tgs = request['T_c_tgs']
        message = request['message']

        decrypted_T_c_tgs = ha.aes_decrypt(
            T_c_tgs['encrypted_message'], 
            TGS_db['TGS'], 
            T_c_tgs['nonce'], 
            T_c_tgs['tag']
        )

        print('------------------------------------------')
        print('Decrypted TGS ticket from the AS server: ')
        print(decrypted_T_c_tgs)
        print('------------------------------------------')

        decrypted_T_c_tgs = json.loads(decrypted_T_c_tgs)

        decrypted_message = ha.aes_decrypt(
            message['encrypted_message'],
            decrypted_T_c_tgs['K_c_tgs'],
            message['nonce'],
            message['tag']
        )

        print('------------------------------------------')
        print('Decrypted message from client with the AS token key: ')
        print(decrypted_message)
        print('------------------------------------------')


        if decrypted_message['ID_S'] in TGS_db:
            K_c_s = ha.random()
            T_A = 5
            N2 = decrypted_message['N2']
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
