# Build a thread safe print function.
# Build a thread safe way to log messages.
# there is no need to maintain information about the last step.

import socket
from _thread import start_new_thread
import threading
import yaml
from yaml.loader import SafeLoader
import algorithms


# read config file
with open('config.yaml', 'r') as f:
    config = yaml.load(f, Loader=SafeLoader)
# get config values
server_address = config['common']['server_address']
server_port = config['common']['server_port']
max_connection = config['server']['max_connection']
log_level = config['server']['log_level']
line = '-' * 100

# clients connected to the server
client_structure_lock = threading.Lock() # since multiple threads will be accessing this structure at the same time we need to protect it with a lock
client_structure = {}

# store server private key
server_rsa_private_key = None

# File lock
file_lock = threading.Lock()

# Count how many clients are ready to generate the shared session key
class ClientReadyForKeyExchange:
    def __init__(self, value):
        self._value = value
        self._lock = threading.Lock()

    @property
    def value(self):
        with self._lock:
            return self._value

    @value.setter
    def value(self, new_value):
        with self._lock:
            self._value = new_value
            self.on_value_change()

    def on_value_change(self):
        broadcast_shared_session_key_message(self._value)

client_ready = ClientReadyForKeyExchange(0)


def broadcast_shared_session_key_message(authenticated_clients):
    if authenticated_clients != max_connection: # if not all clients are authenticated then we don't need to send the shared session key generation message
        return
    
    print('All clients are authenticated, asking clients to start shared session key generation')

    # Once, all the clients are ready for shared key generation
    # Broadcast a message to all the clients to start the process
    # The server does not have any role in this process, except to inform the client to start the process
    server_message_structure = {
        "name": "server-s",
        "command": "request/shared-session-key-generation"
    }

    # send the message to all the clients
    with client_structure_lock:
        for client_name in client_structure:
            client_socket = client_structure[client_name]['client_socket']
            try:
                write_client_message(client_socket, server_message_structure)
            except:
                print(f'err: Could not send shared session key generation message to {client_name}')


def read_client_message(client_socket):
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


def write_client_message(client_socket, message_structure):
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


def send_all_certificates(client_socket, client_message_structure):
    # SEND_CERT
    name = client_message_structure['name']
    # Prepare the list of clients
    clients = {
        "client-a",
        "client-b",
        "client-c",
    }
    clients.remove(name)

    # Read the certificates of the clients
    certificates = {}
    for client in clients:
        certificate_filename = f'certs/{client}.crt'
        with open(certificate_filename, 'rb') as f:
            certificate_data = f.read()
            certificate_data_base64 = algorithms.encode_bytes_to_base64_string(certificate_data)
            certificates[client] = certificate_data_base64

    # Create the server response message
    server_message_structure = {
        "name": "server-s",
        "command": "response/certificates",
        "parameters": {
            "certificates-base64": certificates,
        }
    }

    # Write the server message to client
    write_client_message(client_socket, server_message_structure)


def get_role(client_socket):
    # create the server response message
    server_message_structure = {
        "command": "response/get-role",
        "parameters": {
            "role": "server",
            "name": "server-s",
            "server_address": server_address,
            "server_port": server_port
        }
    }

    # write the server message
    write_client_message(client_socket, server_message_structure)


def send_message(client_message_structure):
    # FORWARD_UNICAST_MESSAGE
    parameters = client_message_structure["parameters"]
    to_client_name = parameters["to"]
    from_client_name = parameters["from"]
    message = parameters["message-base64"]

    # create the server response message
    server_message_structure = {
        "name": "server-s",
        "command": "response/send-message",
        "parameters": {
            "to": to_client_name,
            "from": from_client_name,
            "message-base64": message,
        }
    }

    with client_structure_lock:
        if to_client_name in client_structure:
            client_socket = client_structure[to_client_name]['client_socket']
            write_client_message(client_socket, server_message_structure)
        else:
            print(f'Err: client {to_client_name} not found')
    

def send_message_to_all(client_message_structure):
    # FORWARD_BROADCAST_MESSAGE
    parameters = client_message_structure["parameters"]
    from_client_name = parameters["from"]
    message = parameters["message-base64"]

    with client_structure_lock:
        other_clients = set(client_structure.keys())
        other_clients.remove(from_client_name)
        for client_name in other_clients:
            client_socket = client_structure[client_name]['client_socket']
            # create the server response message
            server_message_structure = {
                "name": "server-s",
                "command": "response/send-message",
                "parameters": {
                    "to": client_name,
                    "from": from_client_name,
                    "message-base64": message,
                }
            }
            write_client_message(client_socket, server_message_structure)


def authenticate_client(client_socket, client_message_structure):
    # VERIFY_AUTH_STEP1
    # Step 1: Server verifies step 1 of client
    # Extract parameters
    client_name = client_message_structure['name']
    parameters = client_message_structure['parameters']
    step = parameters['step']
    client_random_message_base64 = parameters['random-message-base64']
    signature_base64 = parameters['signature-base64']
    
    if step != 1:
        print(f'{client_name} failed step 1 of authentication')
        return False
    
    client_random_message = algorithms.decode_base64_string_to_bytes(client_random_message_base64)
    signature = algorithms.decode_base64_string_to_bytes(signature_base64)
    client_certificate_file = f'certs/{client_name}.crt'
    client_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_file(client_certificate_file)
    is_valid = algorithms.verify_signature_with_rsa_pkcs1v15_and_sha3_256(client_public_key, client_random_message, signature)
    
    if not is_valid:
        print(f'{client_name} failed step 1 of authentication')
        return False

    print(f'server-s verified authentication step 1 for {client_name}')
    
    # AUTH_STEP2
    # Step 2: Server generates authentication message and sends to client
    # Read server certificate and store as base64 string
    with open('certs/server-s.crt', 'rb') as f:
        server_certificate_bytes = f.read()
    server_certificate_base64 = algorithms.encode_bytes_to_base64_string(server_certificate_bytes)
    
    # Encrypt client random message with client public key
    encrypted_client_random_message = algorithms.encrypt_rsa_pkcs1v15(client_public_key, client_random_message)
    encrypted_client_random_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_client_random_message)

    # Generate server random message and encrypt with client public key
    server_random_message = algorithms.generate_random_bytes(32)
    encrypted_server_random_message = algorithms.encrypt_rsa_pkcs1v15(client_public_key, server_random_message)
    encrypted_server_random_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_server_random_message)
    
    # Server signature
    combined_bytes = server_certificate_bytes + encrypted_server_random_message + encrypted_client_random_message
    server_signature = algorithms.sign_with_rsa_pkcs1v15_and_sha3_256(server_rsa_private_key, combined_bytes)
    server_signature_base64 = algorithms.encode_bytes_to_base64_string(server_signature)

    # Create server response message
    server_message_structure = {
        "name": "server-s",
        "command": "response/authenticate",
        "parameters": {
            "step": 2,
            "server-certificate-base64": server_certificate_base64,
            "encrypted-client-random-message-base64": encrypted_client_random_message_base64,
            "encrypted-server-random-message-base64": encrypted_server_random_message_base64,
            "server-signature-base64": server_signature_base64,
        }
    }

    write_client_message(client_socket, server_message_structure)
    print(f'server-s sent step 2 of authentication to {client_name}')

    # VERIFY_AUTH_STEP3
    # Step 3: server verifies step 3 from client
    # read client message
    client_message_structure = read_client_message(client_socket)

    # Extract parameters
    client_name = client_message_structure['name']
    command = client_message_structure['command']
    parameters = client_message_structure['parameters']
    step = parameters['step']
    encrypted_hashed_server_random_message_base64 = parameters['encrypted-hashed-server-random-message-base64']

    if step != 3 and command != 'response/authenticate':
        print(f'err: incorrect step {step} or command {command}')
        return False
    
    # decrypt the encrypted hashed server random message with the server private key
    encrypted_hashed_server_random_message = algorithms.decode_base64_string_to_bytes(encrypted_hashed_server_random_message_base64)
    hashed_server_random_message = algorithms.decrypt_rsa_pkcs1v15(server_rsa_private_key, encrypted_hashed_server_random_message)
    
    # verify the hashed server random message
    if hashed_server_random_message != algorithms.hash_sha3_256(server_random_message):
        print('err: hashed server random message does not match in step 3')
        return False
    
    print(f'server-s verified authentication step 3 for {client_name}')
    print(f'{client_name} authentication success')
    return True


def handle_client(client_socket, client_address):
    # Read client message
    client_message_structure = read_client_message(client_socket)
    
    # Check if client is already connected
    client_name = client_message_structure['name']
    with client_structure_lock:
        client_present = client_name in client_structure
    if client_present:
        print(f'{client_name} is already connected') 
        client_socket.close()
        return
    
    # Store basic client information
    with client_structure_lock:
        client_structure[client_name] = {
            "name": client_name,
            "client_socket": client_socket,
            "client_address": client_address,
        }

    # Before client can send any message, it must be authenticated
    ok = authenticate_client(client_socket, client_message_structure)
    if not ok:
        print(f'{client_name} failed authentication')
        client_socket.close()
        return

    # Client is authenticated, now handle client messages
    while True:
        client_message_structure = read_client_message(client_socket)
        command = client_message_structure['command']
        if command == "request/get-role":
            get_role(client_socket)
            print(f'{client_name} requested server-role')
        elif command == "terminate-connection":
            print(f'{client_name} disconnected')
            break
        elif command == "request/certificates":
            send_all_certificates(client_socket, client_message_structure)
            print(f'{client_name} requested all certificates')
        elif command == "request/send-message":
            send_message(client_message_structure)
            print(f'{client_name} requested to send a message')
        elif command == "request/change-client-ready-state":
            client_ready.value += 1
        elif command == "request/send-message-to-all":
            send_message_to_all(client_message_structure)
            print(f'{client_name} requested to send a broadcast message')
        else:
            print('invalid command')
            break

    # Remove client from client structure
    with client_structure_lock:
        del client_structure[client_name]

    client_ready.value -= 1
    client_socket.close()
    print(f"client {client_name} disconnected")
        

def validate_certificates():
    certs = ['client-a', 'client-b', 'client-c', 'server-s']
    for cert in certs:
        ok = algorithms.validate_certificate_file(f'certs/{cert}.crt')
        if ok:
            print(f'{cert} certificate is valid')
        else:
            print(f'{cert} certificate is invalid')
            exit(1)
        

def run():
    # print config values
    print("server S")
    print('server_address:', server_address)
    print('server_port:', server_port)
    print('max_connection:', max_connection)
    print('log_level:', log_level)

    # Server rsa private key
    global server_rsa_private_key
    with open('certs/server-s.key', 'r') as f:
        server_rsa_private_key = f.read()

    # Validate the certificates once at the start
    validate_certificates()

    # create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind the socket to the address and port
    server_socket.bind((server_address, server_port))

    # listen for max_connection connections
    server_socket.listen(max_connection)

    # accept connections
    while True:
        try:
            # accept a connection
            client_socket, client_address = server_socket.accept()
            # use the start_new_thread() function to create a new thread
            start_new_thread(handle_client, (client_socket, client_address))
        except Exception as e:
            print('err:', e)


if __name__ == "__main__":
    run()
