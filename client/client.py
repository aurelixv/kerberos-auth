#!/usr/bin/env python3
import sys
import socket
import json
from os import system

# Importing from parent directory
sys.path.append('..')
import database as db
import hashing_algorithms as ha

HOST = '127.0.0.1'
AS_PORT = 60001
TGS_PORT = 60002

# Menu
def menu():
    flag = 0
    option = 0
    while flag != 1:
        system('clear')
        while option < 1 or option > 9:
            print('\n --- Client App ---\n')
            print('(1) AS Server')
            print('(2) TGS Server')

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

        if option == 2:
            print('Connecting to the TGS Server...')
            tgs_conn()

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
            message = {}
            message['ID_S'] = 'porta_automatica' #input('Service: ')
            message['T_R'] = 100 #input('Time: ')
            message['N1'] = ha.random()
            message = json.dumps(message)
            
            user_password = input('Enter your password: ')
            variables['user_key'] = ha.hash(user_password).decode('utf-8')
            encrypted_message, nonce, tag = ha.aes_encrypt(message, 
                variables['user_key'])

            request = {
                'action': 'auth',
                'ID_C': client_name,
                'message': {
                    'encrypted_message': encrypted_message,
                    'nonce': nonce, 
                    'tag': tag
                }
            }
            print('------------------------------------------')
            print('Sending to server...')
            print(request)
            print('------------------------------------------')

            s.sendall(json.dumps(request).encode('utf-8'))

            data = s.recv(1024)

            if data:
                data = data.decode('utf-8')
                print('------------------------------------------')
                print('Received from server:')
                print(data)
                print('------------------------------------------')
                try:
                    AS_response = json.loads(data)
                    response = AS_response['response']

                    decrypted = ha.aes_decrypt(response['encrypted_message'], 
                        variables['user_key'], 
                        response['nonce'], 
                        response['tag'])
                    
                    decrypted = json.loads(decrypted)

                    print('------------------------------------------')
                    print('K_c_tgs: ' + decrypted['K_c_tgs'])
                    print('------------------------------------------')

                    variables['K_c_tgs'] = decrypted['K_c_tgs']
                    variables['T_c_tgs'] = AS_response['T_c_tgs']
                    
                except:
                    print(data)
            else:
                print('Server error.')

            input('Press enter to return to the main menu.')

    except ConnectionRefusedError:
        print('Error! AS Server unavailable. Try again later.')
        input('Press enter to return to the main menu.')

# Start the connection with the TGS Server
def tgs_conn():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, TGS_PORT))
            data = s.recv(1024)
            print(data.decode('utf-8'))

            message = {}
            message['ID_C'] = input('Name: ')
            message['ID_S'] = 'porta_automatica' #input('Service: ')
            message['T_R'] = 100 #input('Time: ')
            message['N2'] = ha.random()
            message = json.dumps(message)
            
            encrypted_message, nonce, tag = ha.aes_encrypt(message, 
                variables['K_c_tgs'])

            request = {
                'message': {
                    'encrypted_message': encrypted_message,
                    'nonce': nonce, 
                    'tag': tag
                },
                'T_c_tgs': variables['T_c_tgs']
            }

            print('------------------------------------------')
            print('Sending to server...')
            print(request)
            print('------------------------------------------')

            s.sendall(json.dumps(request).encode('utf-8'))

            data = s.recv(1024)

            if data:
                data = data.decode('utf-8')
                try:
                    AS_response = json.loads(data)
                    print(AS_response)
                    server_responses['AS_response'] = AS_response
                except:
                    print(data)
            else:
                print('Server error.')

            input('Press enter to return to the main menu.')

    except ConnectionRefusedError:
        print('Error! AS Server unavailable. Try again later.')
        input('Press enter to return to the main menu.')

if __name__ == '__main__':
    # For storing responses from servers
    variables = {}

    menu()
