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
PORT = 6001

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
        print(str(conn.getpeername()) + ' sent: ' + str(request))
        message = request['message']

        if request['action'] == 'auth':

            decrypted = ha.aes_decrypt(message['encrypted_message'], 
                AS_db[request['name']], 
                message['nonce'], 
                message['tag']
            )

            print(decrypted)

            conn.sendall(b'Authenticated.')
        else:
            conn.sendall(b'Unknown method.')

    else:
        print('Ending client ' + str(conn.getpeername()) + ' connection...', conn)
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
