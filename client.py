import time
import yaml
import socket
import threading
import algorithms
from yaml.loader import SafeLoader
from _thread import start_new_thread


# read config file
with open('config.yaml', 'r') as f:
    config = yaml.load(f, Loader=SafeLoader)

# get config values
server_address = config['common']['server_address']
server_port = config['common']['server_port']
log_level = config['client']['log_level']

# Store private key
rsa_private_key = None

# Store all the certificates for all the clients sent by the server
certificates = {}

# Store random nonce for each client
random_nonce = {}

# Store shared key
shared_aes_key = None

# Print lock
print_lock = threading.Lock()

# File lock
file_lock = threading.Lock()

# CA public key
ca_public_key = None

line = '-' * 100


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
    # log message disk
    try:
        name = message_structure['name']
        with file_lock:
            with open(f'logs/{name}-log.yaml', 'a') as f:
                f.write(f'\n---')
                f.write(f'\n{message}')
    except Exception as e:
        print(e)


def authenticate(client_socket, name):
    # AUTH_STEP1
    # Step 1: send the client authentication message
    # Create random message of 32 bytes
    random_message = algorithms.generate_random_bytes(32) # has 2^256 possible values
    # Encode this random message to base64 string for transmission
    random_message_base64 = algorithms.encode_bytes_to_base64_string(random_message)
    # Sign the random message with the private key
    signature = algorithms.sign_with_rsa_pkcs1v15_and_sha3_256(rsa_private_key, random_message)
    # Encode the signature to base64 string for transmission
    signature_base64 = algorithms.encode_bytes_to_base64_string(signature)
    # Create the client authentication request message
    client_message_structure = {
        "name": name, # ID of the client
        "command": "request/authenticate",
        "parameters": {
            "step": 1, # 1st step of the authentication process  
            "random-message-base64": random_message_base64,
            "signature-base64": signature_base64
        }
    }
    # Send the client authentication request message
    write_server_message(client_socket, client_message_structure)
    print(f'{name} sent authentication step 1 to server-s')

    # Step 2: read the server authentication response message and verify server
    # Read the server authentication response message
    server_message_structure = read_server_message(client_socket)
    # Extract parameters
    server_name = server_message_structure['name']
    command = server_message_structure['command']
    parameters = server_message_structure['parameters']
    step = parameters['step']
    # Check if the server authentication response message is valid
    if step != 2 or command != 'response/authenticate':
        print(f'err: invalid step {step} or command {command} from server')
        return False

    # VALIDATE_SERVER_CERT
    # Obtain server certificate
    server_certificate_base64 = parameters['server-certificate-base64']
    server_certificate_bytes = algorithms.decode_base64_string_to_bytes(server_certificate_base64)
    server_certificate_string = server_certificate_bytes.decode('utf-8')
    # Validate the server certificate
    is_valid = algorithms.validate_certificate(server_certificate_string)
    if is_valid:
        print(f'{name} validated server-s certificate')
    else:
        print(f'err: {name} failed to validate server-s certificate')
        return False
    # Obtain server public key
    server_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_string(server_certificate_string)

    # Obtain client random message from server
    encrypted_client_random_message_base64 = parameters['encrypted-client-random-message-base64']
    encrypted_client_random_message_bytes = algorithms.decode_base64_string_to_bytes(encrypted_client_random_message_base64)
    client_random_message_bytes = algorithms.decrypt_rsa_pkcs1v15(rsa_private_key, encrypted_client_random_message_bytes)

    # Check if the client random message is valid
    if client_random_message_bytes != random_message:
        print('err: invalid random message')
        return False
    
    # Obtain server random message from server
    encrypted_server_random_message_base64 = parameters['encrypted-server-random-message-base64']
    encrypted_server_random_message_bytes = algorithms.decode_base64_string_to_bytes(encrypted_server_random_message_base64)
    server_random_message_bytes = algorithms.decrypt_rsa_pkcs1v15(rsa_private_key, encrypted_server_random_message_bytes)

    # Obtain server signature from server
    server_signature_base64 = parameters['server-signature-base64']
    server_signature_bytes = algorithms.decode_base64_string_to_bytes(server_signature_base64)

    # Combine server certificate bytes & encrypted server random message bytes & encrypted client random message bytes
    combined_bytes = server_certificate_bytes + encrypted_server_random_message_bytes + encrypted_client_random_message_bytes

    # VERIFY_AUTH_STEP2
    # Verify the server signature
    is_valid = algorithms.verify_signature_with_rsa_pkcs1v15_and_sha3_256(server_public_key, combined_bytes, server_signature_bytes)

    # Check if the server signature is valid
    if not is_valid:
        print('err: invalid signature')
        return False

    print(f'{name} verified authentication step 2 of {server_name}')

    # AUTH_STEP3
    # Step 3: create the client authentication response message
    hash_server_random_message_bytes = algorithms.hash_sha3_256(server_random_message_bytes)
    encrypted_hashed_server_random_message_bytes = algorithms.encrypt_rsa_pkcs1v15(server_public_key, hash_server_random_message_bytes)
    encrypted_hashed_server_random_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_hashed_server_random_message_bytes)
    # Create the client authentication response message
    client_message_structure = {
        "name": name,
        "command": "response/authenticate",
        "parameters": {
            "step": 3, # final step of the authentication process
            "encrypted-hashed-server-random-message-base64": encrypted_hashed_server_random_message_base64
        }
    }

    write_server_message(client_socket, client_message_structure)
    print(f'{name} sent step 3 of authentication to server-s')

    print('authentication success')
    return True


def get_all_certificates(client_socket, name):
    # REQUEST_CERT
    # Make a request to the server to get all the certificates
    client_message_structure = {
        "name": name,
        "command": "request/certificates"
    }

    # Send the client request message
    write_server_message(client_socket, client_message_structure)

    # Read the server response message
    server_message_structure = read_server_message(client_socket)
    command = server_message_structure['command']
    if command != 'response/certificates':
        print(f'err: invalid command {command} from server')
        return False
    
    # Get all the certificates from the server
    parameters = server_message_structure['parameters']
    certificates_base64 = parameters['certificates-base64']
    global certificates

    # VALIDATE_CLIENT_CERT
    for client, certificate_base64 in certificates_base64.items():
        certificate_string = algorithms.decode_base64_string_to_bytes(certificate_base64)
        is_valid = algorithms.validate_certificate(certificate_string)
        if is_valid:
            print(f'certificate of {client} is valid')
        else:
            print(f'err: certificate of {client} is invalid')
            return False

        certificates[client] = certificate_string
    
    print('all certificates received from the server')
    return True


def send_client_ready_message(client_socket, name):
    # Make a request to change the client ready state to True
    client_message_structure = {
        "name": name,
        "command": "request/change-client-ready-state"
    }

    # Send the client request message
    write_server_message(client_socket, client_message_structure)


def share_random_nonce(client_socket, name):
    print('waiting for other clients to connect ...')
    # Wait for the server to respond when all the clients are connected
    server_message_structure = read_server_message(client_socket)

    # check if the server response message is valid    
    command = server_message_structure['command']
    if command != 'request/shared-session-key-generation':
        print('err: invalid command')
        return False
    
    print('all clients are connected, starting shared session key generation ...')
    
    # SHARE_NONCE
    # Make a request to the server to send message to all clients except this client
    client_set = set(certificates.keys())
    client_set.remove(name) # remove this client from the set

    # generate a random nonce and store in global dictionary
    nonce = algorithms.generate_random_bytes(32)
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
        print(f'sent nonce to {client}')

    # Wait for other clients messages to come.
    # Total clients = len(certificates) - 1
    for _ in range(len(certificates) - 1):
        server_message_structure = read_server_message(client_socket)

        # check if the server response message is valid
        command = server_message_structure['command']
        if command != 'response/send-message':
            print('err: invalid command')
            return False
        
        from_client = server_message_structure['parameters']['from']
        message_base64 = server_message_structure['parameters']['message-base64']
        message_yaml_string = algorithms.decode_base64_string_to_bytes(message_base64).decode('utf-8')
        message_structure = yaml.load(message_yaml_string, Loader=yaml.SafeLoader)

        # check if the message structure is valid        
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

        # VERIFY_NONCE
        # verify the signed hash of the encrypted nonce
        from_client_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_string(certificates[from_client])
        is_valid = algorithms.verify_signature_with_rsa_pkcs1v15_and_sha3_256(from_client_public_key, from_client_encrypted_nonce, from_client_signed_hash_encrypted_nonce)
        if not is_valid:
            print('err: invalid signature')
            return False
        
        # RECOVER_NONCE
        # decrypt the encrypted nonce
        from_client_decrypted_nonce = algorithms.decrypt_rsa_pkcs1v15(rsa_private_key, from_client_encrypted_nonce)

        # store the decrypted nonce in the global dictionary
        random_nonce[from_client] = from_client_decrypted_nonce
        print(f'received nonce from {from_client}')


def generate_shared_session_key():
    # GENERATE_SESSION_KEY
    # Make nonce_list in the order of the client names
    clients = [
        'client-a',
        'client-b',
        'client-c',
    ]
    nonce_list = []
    for client in clients:
        nonce_list.append(random_nonce[client])
    
    global shared_aes_key
    shared_aes_key = algorithms.deterministically_combine_bytes(16, nonce_list)


def get_server_role(client_socket):
    # Make a request to the server to get the server's role
    client_message_structure = {
        "command": "request/get-role",
    }
    # send the request message to the server
    write_server_message(client_socket, client_message_structure)


def send_message_to_client(client_socket, from_client, to_client, message, broadcast=False):
    # to client message structure
    to_client_message_structure = {
        "name": from_client,
        "command": "user-message",
        "parameters": {
            "message": message
        }
    }

    # convert the message structure to yaml string
    to_client_message_yaml_string = yaml.dump(to_client_message_structure)

    # encrypt the message with the shared session key
    encrypted_message = algorithms.encrypt_aes_ecb(shared_aes_key, to_client_message_yaml_string.encode('utf-8'))

    # convert the message to base64 string
    encrypted_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_message)

    # prepare the client request message
    client_message_structure = {
        "name": from_client,
        "parameters": {
            "from": from_client,
            "message-base64": encrypted_message_base64
        }
    }

    if broadcast:
        # SEND_BROADCAST_MESSAGE
        client_message_structure['command'] = 'request/send-message-to-all' # If server finds this command it will send message to all clients
    else:
        # SEND_UNICAST_MESSAGE
        client_message_structure['command'] = 'request/send-message' # If server finds this command it will send message to only one client
        client_message_structure['parameters']['to'] = to_client

    # send the client request message
    write_server_message(client_socket, client_message_structure)


def print_message_from_other_clients(server_message_structure):
    # RECV_UNICAST_MESSAGE
    from_client = server_message_structure['parameters']['from']
    message_base64 = server_message_structure['parameters']['message-base64']
    encrypted_message = algorithms.decode_base64_string_to_bytes(message_base64)

    # decrypt the message with the shared session key
    decrypted_message = algorithms.decrypt_aes_ecb(shared_aes_key, encrypted_message).decode('utf-8')

    # convert the message to yaml structure
    message_structure = yaml.load(decrypted_message, Loader=yaml.SafeLoader)

    # check if the message structure is valid
    command = message_structure['command']
    if command != 'user-message':
        print('err: invalid command')
        return False
    
    message = message_structure['parameters']['message']

    print(f'{from_client} > {message}')


def wait_for_messages_from_server(client_socket, name):
    while True:
    # Get message from the server
        server_message_structure = read_server_message(client_socket)

        # Validate the server response message
        command = server_message_structure['command']
        if command == 'response/send-message':
            print()
            print_message_from_other_clients(server_message_structure)
        elif command == 'response/get-role':
            print()
            print('server role')
            print('-----------')
            yaml_string = yaml.dump(server_message_structure, sort_keys=False)
            print(yaml_string)


def handle_user_input(client_socket, name):
    # Give user options to perform several actions
    while True:
        try:
            print(f'{name} > ', end='')
            inp = input()
            inps = inp.split(' ')
            cmd = inps[0]
            options = inps[1:]
            
            if cmd == '-e':
                print('exiting...')
                break
            
            elif cmd == '-s':
                get_server_role(client_socket)
                time.sleep(0.2) # wait for the server to respond
            
            elif cmd == '-h':
                print()
                print('help')
                print('----')
                print('-h: To show this message')
                print('-s: To get server roles')
                print('-c <client-short-name> -m <msg>: To send message to client')
                print('-b -m <msg>: To broadcast message to all clients except self')
                print('-e: To exit the program')
                print()

            elif cmd == '-c':
                from_client = name
                to_client = f'client-{options[0]}'
                inps = inp.split('-m')
                message = inps[1].strip()
                print(f'sending message to {to_client}')
                send_message_to_client(client_socket, from_client, to_client, message)
        
            elif cmd == '-b':
                print('broadcasting message to all clients')
                from_client = name
                to_client = 'all' # Dummy value only
                inps = inp.split('-m')
                message = inps[1].strip()
                send_message_to_client(client_socket, from_client, to_client, message, broadcast=True)
        
        except Exception as e:
            print('err:', e)
            print('err: invalid syntax')


def run(short_name='a'):
    name = f'client-{short_name}'
    # Print config values
    print('client:', name)
    print('server_address:', server_address)
    print('server_port:', server_port)
    print('log_level:', log_level)

    # Store client rsa private key
    global rsa_private_key
    with open(f'certs/{name}.key', 'r') as f:
        rsa_private_key = f.read()
    
    # Store ca public key
    global ca_public_key
    with open('certs/ca.pub.pem', 'r') as f:
        ca_public_key = f.read()

    # Store the client certificate
    global certificates
    with open(f'certs/{name}.crt', 'r') as f:
        certificates[name] = f.read()

    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect((server_address, server_port))

    # Authenticate with the server
    ok = authenticate(client_socket, name)
    if not ok:
        client_socket.close()
        print('err: authentication failed')
        return

    # Get all certificates for all the clients from the server
    get_all_certificates(client_socket, name)

    # Inform the this instance of the client is ready to start the shared session key generation
    send_client_ready_message(client_socket, name)

    # Wait for the other clients to connect
    share_random_nonce(client_socket, name)

    # Generate the shared session key
    generate_shared_session_key()

    # Print the shared session key
    print('shared session key:', shared_aes_key)

    # Start another thread to wait for messages from other clients using start_new_thread()
    start_new_thread(wait_for_messages_from_server, (client_socket, name))

    handle_user_input(client_socket, name)
    
    # Make terminate connection message
    client_message_structure = {
        "name": name, # ID of the client
        "command": "terminate-connection",
    }

    # Send terminate connection message to server
    write_server_message(client_socket, client_message_structure)
    client_socket.close()


if __name__ == '__main__':
    run()
