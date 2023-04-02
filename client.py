import socket
import yaml
import algorithms
from yaml.loader import SafeLoader


# read config file
with open('config.yaml', 'r') as f:
    config = yaml.load(f, Loader=SafeLoader)


# get config values
server_address = config['common']['server_address']
server_port = config['common']['server_port']
log_level = config['client']['log_level']

line = '-' * 80


# store private key
rsa_private_key = None


# store all the certificates for all the clients sent by the server
certificates = {}


# Store random nonce for each client
random_nonce = {}


def read_server_message(client_socket):
    # first read the length of the message as a 4 byte integer
    length_bytes = client_socket.recv(4)
    # convert the length bytes to an integer
    length = int.from_bytes(length_bytes, byteorder='big')
    # read the message
    message_bytes = client_socket.recv(length)
    # convert the message bytes to a string
    message = message_bytes.decode('utf-8')
    # decode the message as a yaml object
    message_structure = yaml.load(message, Loader=SafeLoader)
    # return the message structure
    return message_structure


def write_server_message(client_socket, message_structure):
    # encode the message structure as a yaml string
    message = yaml.dump(message_structure)
    # convert the message to bytes
    message_bytes = bytes(message, 'utf-8')
    # get the length of the message
    length = len(message_bytes)
    # convert the length to bytes
    length_bytes = length.to_bytes(4, byteorder='big')
    # send the length bytes
    client_socket.sendall(length_bytes)
    # send the message bytes
    client_socket.sendall(message_bytes)


def get_server_role(client_socket):
    # Make a request to the server to get the server's role
    client_message_structure = {
        "version": 0,
        "command": "request/get-role",
    }

    # send the request message to the server
    write_server_message(client_socket, client_message_structure)

    # read the server response message
    server_message_structure = read_server_message(client_socket)

    # return the string of server response message
    message = yaml.dump(server_message_structure)
    return message


def authenticate(client_socket, name):
    # step 1: send the client authentication request message
    # create random message of 32 bytes
    random_message = algorithms.generate_random_bytes(32) # has 2^256 possible values
    # Encode this random message to base64 string for transmission
    random_message_base64 = algorithms.encode_bytes_to_base64_string(random_message)
    # sign the random message with the private key
    signature = algorithms.sign_with_rsa_pkcs1v15_and_sha3_256(rsa_private_key, random_message)
    # Encode the signature to base64 string for transmission
    signature_base64 = algorithms.encode_bytes_to_base64_string(signature)

    # create the client authentication request message
    client_message_structure = {
        "version": 0,
        "name": name, # ID of the client
        "command": "request/authenticate",
        "parameters": {
            "step": 1, # 1st step of the authentication process  
            "random-message-base64": random_message_base64,
            "signature-base64": signature_base64
        }
    }

    # send the client authentication request message
    write_server_message(client_socket, client_message_structure)

    # step 2: read the server authentication response message and verify server
    # read the server authentication response message
    server_message_structure = read_server_message(client_socket)

    # check if the server authentication response message is valid
    if server_message_structure['version'] != 0:
        print('err: invalid version')
        client_socket.close()
        return False
    
    # check if the server authentication response message is valid
    step = server_message_structure['parameters']['step']
    command = server_message_structure['command']
    if step != 2 or command != 'response/authenticate':
        print(f'err: invalid step {step} or command {command}')
        client_socket.close()
        return False

    # obtain server certificate & public key
    server_certificate_base64 = server_message_structure['parameters']['server-certificate-base64']
    server_certificate_bytes = algorithms.decode_base64_string_to_bytes(server_certificate_base64)
    server_certificate_string = server_certificate_bytes.decode('utf-8')
    server_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_string(server_certificate_string)

    # obtain client random message from server
    encrypted_client_random_message_base64 = server_message_structure['parameters']['encrypted-client-random-message-base64']
    encrypted_client_random_message_bytes = algorithms.decode_base64_string_to_bytes(encrypted_client_random_message_base64)
    client_random_message_bytes = algorithms.decrypt_rsa_pkcs1v15(rsa_private_key, encrypted_client_random_message_bytes)

    # check if the client random message is valid
    if client_random_message_bytes != random_message:
        print('err: invalid random message')
        client_socket.close()
        return False
    
    # obtain server random message from server
    encrypted_server_random_message_base64 = server_message_structure['parameters']['encrypted-server-random-message-base64']
    encrypted_server_random_message_bytes = algorithms.decode_base64_string_to_bytes(encrypted_server_random_message_base64)
    server_random_message_bytes = algorithms.decrypt_rsa_pkcs1v15(rsa_private_key, encrypted_server_random_message_bytes)

    # obtain server signature from server
    server_signature_base64 = server_message_structure['parameters']['server-signature-base64']
    server_signature_bytes = algorithms.decode_base64_string_to_bytes(server_signature_base64)

    # combine server certificate bytes & encrypted server random message bytes & encrypted client random message bytes
    combined_bytes = server_certificate_bytes + encrypted_server_random_message_bytes + encrypted_client_random_message_bytes

    # verify the server signature
    is_valid = algorithms.verify_signature_with_rsa_pkcs1v15_and_sha3_256(server_public_key, combined_bytes, server_signature_bytes)

    # check if the server signature is valid
    if not is_valid:
        print('err: invalid signature')
        client_socket.close()
        return False
    
    # print second step of the authentication process is successful
    print('server successfully authenticated, step 2 okay')

    # step 3: create the client authentication response message
    hash_server_random_message_bytes = algorithms.hash_sha3_256(server_random_message_bytes)
    encrypted_hashed_server_random_message_bytes = algorithms.encrypt_rsa_pkcs1v15(server_public_key, hash_server_random_message_bytes)
    encrypted_hashed_server_random_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_hashed_server_random_message_bytes)
    client_message_structure = {
        "version": 0,
        "name": name, # ID of the client
        "command": "response/authenticate",
        "parameters": {
            "step": 3, # final step of the authentication process
            "encrypted-hashed-server-random-message-base64": encrypted_hashed_server_random_message_base64
        }
    }

    # send the client authentication response message
    write_server_message(client_socket, client_message_structure)

    print('authentication process successful')
    return True


def get_all_certificates(client_socket, name):
    # Make a request to the server to get all the certificates
    client_message_structure = {
        "version": 0,
        "name": name,
        "command": "request/certificates"
    }

    # send the client request message
    write_server_message(client_socket, client_message_structure)

    # read the server response message
    server_message_structure = read_server_message(client_socket)

    # read all the certificates from the server
    certificates_base64 = server_message_structure['parameters']['certificates-base64']
    global certificates

    for client, certificate_base64 in certificates_base64.items():
        certificate_bytes = algorithms.decode_base64_string_to_bytes(certificate_base64)
        certificate_string = certificate_bytes.decode('utf-8')
        certificates[client] = certificate_string
    
    print('all certificates received from the server')


def send_client_ready_message(client_socket, name):
    # Make a request to change the client ready state to True
    client_message_structure = {
        "version": 0,
        "name": name,
        "command": "request/change-client-ready-state"
    }

    # Send the client request message
    write_server_message(client_socket, client_message_structure)


def wait_for_other_clients(client_socket, name):
    print("waiting for other clients to connect ...")
    # Wait for the server to respond when all the clients are connected
    server_message_structure = read_server_message(client_socket)

    # check if the server response message is valid
    if server_message_structure['version'] != 0:
        print('err: invalid server version')
        return False
    
    command = server_message_structure['command']

    if command != 'request/shared-session-key-generation':
        print('err: invalid command')
        return False
    
    print("all clients are connected, starting shared session key generation ...")
    
    # Make a request to the server to send message to all clients except this client
    client_set = set(certificates.keys())
    client_set.remove(name) # remove this client from the set

    # generate a random nonce
    nonce = algorithms.generate_random_bytes(32)
    # nonce = b'12345678901234567890123456789012'
    # store the nonce in the global dictionary
    global random_nonce
    random_nonce[name] = nonce

    for client in client_set:
        # encrypt the nonce with the client's public key
        client_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_string(certificates[client])
        encrypted_nonce = algorithms.encrypt_rsa_pkcs1v15(client_public_key, nonce)
        signed_hash_encrypted_nonce = algorithms.sign_with_rsa_pkcs1v15_and_sha3_256(rsa_private_key, encrypted_nonce)
        encrypted_nonce_base64 = algorithms.encode_bytes_to_base64_string(encrypted_nonce)
        signed_hash_encrypted_nonce_base64 = algorithms.encode_bytes_to_base64_string(signed_hash_encrypted_nonce)
        
        # create the "to message structure" for the recipient client
        to_client_message_structure = {
            "version": 0,
            "name": name,
            "command": "control-message/nonce",
            "parameters": {
                "encrypted-nonce-base64": encrypted_nonce_base64,
                "signed-hash-encrypted-nonce-base64": signed_hash_encrypted_nonce_base64
            }
        }

        # Convert the "to message structure" to yaml string
        to_client_message_yaml_string = yaml.dump(to_client_message_structure)

        # Convert the yaml string to base64 string
        to_client_message_yaml_string_base64 = algorithms.encode_bytes_to_base64_string(to_client_message_yaml_string.encode())

        # prepare the client request message
        client_message_structure = { # for the current client
            "version": 0,
            "name": name,
            "command": "request/send-message",
            "parameters": {
                "to": client,
                "from": name,
                "message-base64": to_client_message_yaml_string_base64
            }
        }

        # send the client request message
        write_server_message(client_socket, client_message_structure)

        print(f"sent nonce to {client}")

    # Wait for other clients messages to come.
    # Total clients = len(certificates) - 1
    for _ in range(len(certificates) - 1):
        server_message_structure = read_server_message(client_socket)

        # log the server response message to the disk
        with open(f'{name}-log.yaml', 'a') as f:
            f.write('\n' + f'server_message_structure: {yaml.dump(server_message_structure)}')

        # check if the server response message is valid
        if server_message_structure['version'] != 0:
            print('err: invalid server version')
            return False
        
        command = server_message_structure['command']

        if command != 'response/send-message':
            print('err: invalid command')
            return False
        
        from_client = server_message_structure['parameters']['from']
        message_base64 = server_message_structure['parameters']['message-base64']
        message_yaml_string = algorithms.decode_base64_string_to_bytes(message_base64).decode('utf-8')
        message_structure = yaml.load(message_yaml_string, Loader=yaml.SafeLoader)

        # check if the message structure is valid
        if message_structure['version'] != 0:
            print('err: invalid message version')
            return False
        
        command = message_structure['command']

        if command != 'control-message/nonce':
            print('err: invalid command')
            return False

        # get the encrypted nonce from the message
        from_client_encrypted_nonce_base64 = message_structure['parameters']['encrypted-nonce-base64']
        from_client_encrypted_nonce = algorithms.decode_base64_string_to_bytes(from_client_encrypted_nonce_base64)

        # get the signed hash of the encrypted nonce from the message
        from_client_signed_hash_encrypted_nonce_base64 = message_structure['parameters']['signed-hash-encrypted-nonce-base64']
        from_client_signed_hash_encrypted_nonce = algorithms.decode_base64_string_to_bytes(from_client_signed_hash_encrypted_nonce_base64)

        # verify the signed hash of the encrypted nonce
        from_client_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_string(certificates[from_client])
        is_valid = algorithms.verify_signature_with_rsa_pkcs1v15_and_sha3_256(from_client_public_key, from_client_encrypted_nonce, from_client_signed_hash_encrypted_nonce)
        if not is_valid:
            print('err: invalid signature')
            return False
        
        # decrypt the encrypted nonce
        from_client_decrypted_nonce = algorithms.decrypt_rsa_pkcs1v15(rsa_private_key, from_client_encrypted_nonce)

        # store the decrypted nonce in the global dictionary
        random_nonce[from_client] = from_client_decrypted_nonce

        print(f"received nonce from {from_client}")


def run(name='client-a'):
    # print config values
    print(line)
    print('client:', name)
    print(line)
    print('server_address:', server_address)
    print('server_port:', server_port)
    print('log_level:', log_level)
    print(line)

    # read rsa private key
    global rsa_private_key
    rsa_private_key = algorithms.get_private_key_pem_format_from_keyfile(f'certs/{name}.key')
    
    # create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect to the server
    client_socket.connect((server_address, server_port))

    # authenticate with the server
    authenticate(client_socket, name)

    # get all certificates for all the clients from the server
    get_all_certificates(client_socket, name)

    # inform the this instance of the client is ready to start the shared session key generation
    send_client_ready_message(client_socket, name)

    # Wait for the other clients to connect
    wait_for_other_clients(client_socket, name)

    # Give user options to perform several actions
    while True:
        print('1. Get server role')
        print('2. Send message to server')
        print('3. Exit')
        choice = input('Enter your choice: ')
        
        if choice == '1':
            server_role = get_server_role(client_socket)
            print('server role:', server_role)
        
        elif choice == '3':
            break
    
    # Make terminate connection message
    client_message_structure = {
        "version": 0,
        "name": name, # ID of the client
        "command": "terminate-connection",
    }

    # Send terminate connection message to server
    write_server_message(client_socket, client_message_structure)
    client_socket.close()


if __name__ == '__main__':
    run()
