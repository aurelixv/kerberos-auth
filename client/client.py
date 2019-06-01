#!/usr/bin/env python3
import sys
import socket
import json
from os import system

# Importing from parent directory
sys.path.append('..')
import database as db
import hashing_algorithms as ha

# Menu
def menu():
    flag = 0
    option = 0
    while flag != 1:
        system('clear')
        while option < 1 or option > 9:
            print('\n --- Client App ---\n')
            print('(1) AS Server')

            print('(9) Exit')
            option = input('>>: ')
            try:
                option = int(option)
            except ValueError:
                system('clear')
                print('Invalid option!')
                option = 0
            else:
                system('clear')

        if option == 1:
            print('Connecting to the AS Server...')
            as_conn()


        elif option == 9:
            flag = 1

        option = 0

# Start the connection with the AS Server
def as_conn():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, AS_PORT))
            data = s.recv(1024)
            print(data.decode('utf-8'))

            client_name = input('Name: ')
            encrypted_message = input('Debug message: ')
            encrypted_message, nonce, tag = ha.aes_encrypt(encrypted_message, client_db['aurelio'])

            request = {
                'action': 'auth',
                'name': client_name,
                'message': {'encrypted_message': encrypted_message, 'nonce': nonce, 'tag': tag}
            }

            s.sendall(json.dumps(request).encode('utf-8'))

            data = s.recv(1024)

            if data:
                print(data.decode('utf-8'))
            else:
                print('Server error.')

            input('Press enter to return to the main menu.')

    except ConnectionRefusedError:
        print('Error! AS Server unavailable. Try again later.')
        input('Press enter to return to the main menu.')

if __name__ == '__main__':
    HOST = '127.0.0.1'
    AS_PORT = 6001

    client_db = db.load_database('client_db')
    db.insert(client_db, 'aurelio', ha.hash('master_password').decode('utf-8'))

    menu()

    db.save_database('client_db', client_db)
