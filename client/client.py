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
            
            if len(variables) > 0:
                for variable in variables:
                    print(str(variable) + ': ' + str(variables[variable]))
                print('')

            print('(1) AS Server')
            print('(2) TGS Server')
            print('(3) Generate Service Ticket')

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

        if option == 3:
            print('Generating Service Ticket...')
            service_ticket()

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

            variables['ID_C'] = input('Name: ')
            variables['ID_S'] = 'service' #input('Service: ')
            variables['T_R'] = 100 #input('Time: ')
            variables['K_c'] = ha.hash(input('Enter your password: ')).decode('utf-8')
            
            message = {
                'ID_S': variables['ID_S'],
                'T_R': variables['T_R'],
                'N1': ha.random(16)
            }
            message = json.dumps(message)

            print('------------------------------------------')
            print('Message:')
            print(message)
            print('------------------------------------------')
            print('K_c:')
            print(variables['K_c'])
            
            encrypted_message, nonce, tag = ha.aes_encrypt(message, variables['K_c'])

            request = {
                #'action': 'auth',
                'ID_C': variables['ID_C'],
                'message': {
                    'encrypted_message': encrypted_message,
                    'nonce': nonce, 
                    'tag': tag
                }
            }
            print('------------------------------------------')
            print('Sending M1 to server...')
            print(request)

            s.sendall(json.dumps(request).encode('utf-8'))

            data = s.recv(1024)

            if data:
                try:
                    data = data.decode('utf-8')
                    AS_response = json.loads(data)
                    response = AS_response['response']
                    
                    print('------------------------------------------')
                    print('Received M2 from server:')
                    print(data)

                    decrypted = ha.aes_decrypt(response['encrypted_message'], 
                        variables['K_c'], 
                        response['nonce'], 
                        response['tag'])
                    
                    decrypted = json.loads(decrypted)

                    print('------------------------------------------')
                    print('Decrypted response:')
                    print(decrypted)
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

    if 'K_c_tgs' not in variables:
        input('Error: K_c_tgs not defined.')
        return

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, TGS_PORT))
            data = s.recv(1024)
            print(data.decode('utf-8'))

            message = {
                'ID_C': variables['ID_C'],
                #'ID_C': 'teste',
                'ID_S': variables['ID_S'],
                'T_R': variables['T_R'],
                #'T_R': 1,
                'N2': ha.random(16)
            }
            message = json.dumps(message)

            print('------------------------------------------')
            print('Message:')
            print(message)
            print('------------------------------------------')
            print('K_c_tgs:')
            print(variables['K_c_tgs'])
            
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
            print('Sending M3 to server...')
            print(request)

            s.sendall(json.dumps(request).encode('utf-8'))

            data = s.recv(1024)

            if data:
                try:
                    data = data.decode('utf-8')
                    TGS_response = json.loads(data)
                    response = TGS_response['response']
                    T_c_s = TGS_response['T_c_s']

                    print('------------------------------------------')
                    print('Received M4 from server:')
                    print(data)
                    
                    decrypted = ha.aes_decrypt(
                        response['encrypted_message'],
                        variables['K_c_tgs'],
                        response['nonce'],
                        response['tag']
                    )

                    decrypted = json.loads(decrypted)

                    print('------------------------------------------')
                    print('Decrypted response:')
                    print(decrypted)
                    print('------------------------------------------')

                    variables['K_c_s'] = decrypted['K_c_s']
                    variables['T_c_s'] = T_c_s
                    variables['T_A'] = str(decrypted['T_A'])
                except:
                    print(data)
            else:
                print('Server error.')

            input('Press enter to return to the main menu.')

    except ConnectionRefusedError:
        print('Error! AS Server unavailable. Try again later.')
        input('Press enter to return to the main menu.')

# Generate the Service Ticket
def service_ticket():

    # M5 = [{ID_C + (T_A ou T_R) + S_R + N3}K_c_s + T_c_s]

    if 'K_c_s' not in variables:
        input('Error: K_c_s not defined.')
        return

    request = {
        'ID_C': variables['ID_C'],
        'T_A': variables['T_A'],
        'S_R': variables['ID_S'],
        'N3': ha.random(16)
    }
    request = json.dumps(request)

    print('------------------------------------------')
    print('Message:')
    print(request)

    encrypted_message, nonce, tag = ha.aes_encrypt(request, variables['K_c_s'])
    request = {
        'encrypted_message': encrypted_message,
        'nonce': nonce,
        'tag': tag,
    }
    request = {'message': request, 'T_c_s': variables['T_c_s']}

    print('------------------------------------------')
    print('Saving M5 Service Ticket...')
    print(request)
    print('------------------------------------------')

    db.save_database('service_ticket', request)
    input('Press enter to return to the main menu.')

if __name__ == '__main__':
    # For storing responses from servers
    variables = {}

    menu()
