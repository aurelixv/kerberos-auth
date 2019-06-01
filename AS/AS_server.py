#!/usr/bin/env python3
import sys
import socket
import selectors
import json
from time import sleep

HOST = '127.0.0.1'
PORT = 6001

sel = selectors.DefaultSelector()

print('Starting AS server at ' + HOST + ' port ' + str(PORT))

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

        if request['action'] == 'auth':
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
