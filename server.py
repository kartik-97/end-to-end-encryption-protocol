# Build a thread safe print function.
# Build a thread safe way to log messages.
# clean your authentication code.
# there is no need to maintain information about the last step.
# close connection with client on authentication failure.
# merge the two functions authenticate and authenticate_final
# no need to return True or False from authenticate
# allow services to clients only when authentication is successful.

import socket
from _thread import start_new_thread
import threading
import yaml
from yaml.loader import SafeLoader
import algorithms
import copy


# read config file
with open('config.yaml', 'r') as f:
    config = yaml.load(f, Loader=SafeLoader)


# get config values
server_address = config['common']['server_address']
server_port = config['common']['server_port']
max_connection = config['server']['max_connection']
log_level = config['server']['log_level']
line = '-' * 80


# clients connected to the server
client_structure_lock = threading.Lock() # since multiple threads will be accessing this structure at the same time we need to protect it with a lock
client_structure = {}

# store server private key
server_rsa_private_key = None


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
    print(f'authenticated_clients: {authenticated_clients}')
    if authenticated_clients != max_connection: # if not all clients are authenticated then we don't need to send the shared session key generation message
        return
    
    # Just tell the clients that all the clients are connected and authenticated
    # Now they can share random nonce with each other and generate the shared session key
    # The server does not have any role in this process, except to tell the clients that they can start the process
    server_message_structure = {
        "version": 0,
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
                print(f'Err: Could not send shared session key generation message to client: {client_name}')


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


def send_all_certificates(client_socket):
    # Prepare the list of clients
    clients = [
        "client-a",
        "client-b",
        "client-c",
    ]

    # Read the certificates of the clients
    certificates = {}
    for client in clients:
        certificate_filename = f"certs/{client}.crt"
        with open(certificate_filename, 'rb') as f:
            certificate_data = f.read()
            certificate_data_base64 = algorithms.encode_bytes_to_base64_string(certificate_data)
            certificates[client] = certificate_data_base64

    # Create the server response message
    server_message_structure = {
        "version": 0,
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
        "version": 0,
        "command": "response/get-role",
        "parameters": {
            "role": "server",
            "name": "S",
            "server_address": server_address,
            "server_port": server_port
        }
    }

    # write the server message
    write_client_message(client_socket, server_message_structure)


def send_message(client_message_structure):
    to_client_name = client_message_structure["parameters"]["to"]
    from_client_name = client_message_structure["parameters"]["from"]
    message = client_message_structure["parameters"]["message-base64"]

    # create the server response message
    server_message_structure = {
        "version": 0,
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
            # write the server message
            write_client_message(client_socket, server_message_structure)
        else:
            print(f'Err: client {to_client_name} not found')
    

# Step 3: server verifies client
def authenticate_final(client_socket, server_random_message):
    # read client message
    client_message_structure = read_client_message(client_socket)

    step = client_message_structure["parameters"]["step"]
    name = client_message_structure["name"]
    command = client_message_structure["command"]

    if step != 3 and command != "response/authenticate":
        print(f'err: incorrect step {step} or command {command}')
        return False
    
    encrypted_hashed_server_random_message_base64 = client_message_structure["parameters"]["encrypted-hashed-server-random-message-base64"]
    encrypted_hashed_server_random_message = algorithms.decode_base64_string_to_bytes(encrypted_hashed_server_random_message_base64)

    # decrypt the encrypted hashed server random message with the server private key
    hashed_server_random_message = algorithms.decrypt_rsa_pkcs1v15(server_rsa_private_key, encrypted_hashed_server_random_message)
    
    if hashed_server_random_message != algorithms.hash_sha3_256(server_random_message):
        print('err: hashed server random message does not match in step 3')
        return False
    
    client_structure_lock.acquire()
    client_structure[name]["authenticated"] = True
    client_structure[name]["last_authenticated_step"] = 3
    client_structure_lock.release()
    
    print('authentication success')
    return True


# Step 2: Client will verify step 2 of server
def authenticate_server_with_client(client_socket, client_message_structure):
    # Read server certificate and store as base64 string
    with open('certs/server-s.crt', 'rb') as f:
        server_certificate_bytes = f.read()
    server_certificate_base64 = algorithms.encode_bytes_to_base64_string(server_certificate_bytes)
    
    # Encrypt client random message with client public key
    name = client_message_structure["name"]
    client_public_key_file = f'certs/{name}.crt'
    client_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_file(client_public_key_file)
    client_random_message_base64 = client_message_structure["parameters"]["random-message-base64"]
    client_random_message = algorithms.decode_base64_string_to_bytes(client_random_message_base64)
    encrypted_client_random_message = algorithms.encrypt_rsa_pkcs1v15(client_public_key, client_random_message)
    encrypted_client_random_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_client_random_message)

    # Sign server random message with server private key
    server_random_message = algorithms.generate_random_bytes(32)
    encrypted_server_random_message = algorithms.encrypt_rsa_pkcs1v15(client_public_key, server_random_message)
    encrypted_server_random_message_base64 = algorithms.encode_bytes_to_base64_string(encrypted_server_random_message)
    
    # server signature
    combined_bytes = server_certificate_bytes + encrypted_server_random_message + encrypted_client_random_message
    server_signature = algorithms.sign_with_rsa_pkcs1v15_and_sha3_256(server_rsa_private_key, combined_bytes)
    server_signature_base64 = algorithms.encode_bytes_to_base64_string(server_signature)

    # Create server response message
    server_message_structure = {
        "version": 0,
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

    # write the server message
    write_client_message(client_socket, server_message_structure)

    # final step
    return authenticate_final(client_socket, server_random_message)


# Step 1: Server verifies step 1 of client
def authenticate_client(client_socket, client_message_structure):
    try:
        parameters = client_message_structure["parameters"]
        step = parameters["step"]
        name = client_message_structure["name"]

        if step == 1:
            random_message_base64 = parameters["random-message-base64"]
            signature_base64 = parameters["signature-base64"]
            random_message = algorithms.decode_base64_string_to_bytes(random_message_base64)
            signature = algorithms.decode_base64_string_to_bytes(signature_base64)
            rsa_public_key_file = f'certs/{name}.crt'
            rsa_public_key = algorithms.get_public_key_pem_format_from_self_signed_certificate_file(rsa_public_key_file)
            is_valid = algorithms.verify_signature_with_rsa_pkcs1v15_and_sha3_256(rsa_public_key, random_message, signature)
            if is_valid:
                client_structure_lock.acquire()
                client_structure[name]["last_authenticated_step"] = 1
                client_structure_lock.release()
                print(f'client {name} completed step 1 of authentication')
                return authenticate_server_with_client(client_socket, client_message_structure)
            else:
                print(f'client {name} failed step 1 of authentication')
                return False
        else:
            print(f'client {name} failed step 1 of authentication')
            return False
    
    except Exception as e:
        print('err:', e)
        return False


def handle_client(client_socket, client_address):
    client_message_structure = read_client_message(client_socket)
    
    name = client_message_structure["name"]
    
    client_structure_lock.acquire()
    client_present = name in client_structure
    client_structure_lock.release()
    
    if client_present:
        print(f'client {name} is already connected') # Some random client can force other clients to disconnect if they know the name
        client_socket.close()
        return
    
    # store basic client information
    with client_structure_lock:
        client_structure[name] = {
            "name": name,
            "authenticated": False,
            "last_authenticated_step": 0,
            "client_socket": client_socket,
            "client_address": client_address,
        }

    try:
        # Before client can send any message, it must be authenticated
        ok = authenticate_client(client_socket, client_message_structure)
        
        if not ok:
            print(f'client {name} failed authentication')
        else:
            # read the client message till the client terminates the connection
            while True:
                client_message_structure = read_client_message(client_socket)
                if client_message_structure["version"] != 0:
                    print('invalid version')
                    break
                if client_message_structure["command"] == "request/get-role":
                    get_role(client_socket)
                    print(f'client {name} requested server-role')
                elif client_message_structure["command"] == "terminate-connection":
                    print(f'client {name} disconnected')
                    break
                elif client_message_structure["command"] == "request/certificates":
                    send_all_certificates(client_socket)
                    print(f'client {name} requested all certificates')
                elif client_message_structure["command"] == "request/send-message":
                    send_message(client_message_structure)
                    print(f'client {name} requested to send a message')
                elif client_message_structure["command"] == "request/change-client-ready-state":
                    client_ready.value += 1
                else:
                    print('invalid command')
                    break
    except Exception as e:
        print('err:', e)

    # remove client from client structure
    with client_structure_lock:
        del client_structure[name]

    # decrease the number of ready clients
    client_ready.value -= 1

    client_socket.close()

    print(f"client {name} disconnected")
        

def run():
    # print config values
    print(line)
    print("server S")
    print(line)
    print('server_address:', server_address)
    print('server_port:', server_port)
    print('max_connection:', max_connection)
    print('log_level:', log_level)
    print(line)


    # Server rsa private key
    global server_rsa_private_key
    server_rsa_private_key_file = 'certs/server-s.key'
    server_rsa_private_key = algorithms.get_private_key_pem_format_from_keyfile(server_rsa_private_key_file)

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
            # print the client address
            print('client connected:', client_address)
            # use the start_new_thread() function to create a new thread
            start_new_thread(handle_client, (client_socket, client_address))
        except Exception as e:
            print('err:', e)


if __name__ == "__main__":
    run()
