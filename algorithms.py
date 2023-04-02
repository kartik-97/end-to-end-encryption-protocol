from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from base64 import b64decode
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA3_256
import base64
from Crypto.Signature import pkcs1_15


def hash_sha3_256(data_bytes):
    # Create a SHA3-256 hasher object
    hasher = SHA3_256.new()
    # Update the hasher with the plaintext
    hasher.update(data_bytes)
    # Return the hash digest
    return hasher.digest()


def generate_random_bytes(length):
    return get_random_bytes(length)


def generate_aes_random_key():
    return get_random_bytes(16)


def encrypt_aes_ecb(key, plaintext_bytes):
    # Encrypt using AES in ECB mode
    # Create a cipher object
    aes_cipher = AES.new(key, AES.MODE_ECB)
    # Get the aes block size to pad the plaintext
    block_size = aes_cipher.block_size
    # Pad the plaintext
    padded_plaintext_bytes = pad(plaintext_bytes, block_size)
    # Encrypt the padded plaintext
    ciphertext_bytes = aes_cipher.encrypt(padded_plaintext_bytes)
    # Return the ciphertext
    return ciphertext_bytes


def decrypt_aes_ecb(key, ciphertext_bytes):
    # Decrypt using AES in ECB mode
    # Create a cipher object
    aes_cipher = AES.new(key, AES.MODE_ECB)
    # Get the aes block size to pad the plaintext
    block_size = aes_cipher.block_size
    # Decrypt the ciphertext
    padded_plaintext_bytes = aes_cipher.decrypt(ciphertext_bytes)
    # Unpad the plaintext
    plaintext_bytes = unpad(padded_plaintext_bytes, block_size)
    # Return the plaintext
    return plaintext_bytes


def get_public_key_pem_format_from_self_signed_certificate_string(pem_data):
    # Remove the BEGIN and END lines from the certificate
    lines = pem_data.strip().split('\n')
    base64_data = ''
    for line in lines:
        if not line.startswith('-----'):
            base64_data += line

    # Decode the base64 data and parse the ASN.1 structure
    der_data = b64decode(base64_data)
    asn1_data = asn1.DerSequence()
    asn1_data.decode(der_data)

    # Extract the SubjectPublicKeyInfo (SPKI) part of the certificate
    tbs_certificate = asn1.DerSequence()
    tbs_certificate.decode(asn1_data[0])
    spki = tbs_certificate[5]

    # Extract the public key from the SPKI
    rsa_key = RSA.import_key(spki)
    return rsa_key.publickey().export_key()


def get_public_key_pem_format_from_self_signed_certificate_file(filename):
    with open(filename, 'r') as f:
        pem_data = f.read()
    return get_public_key_pem_format_from_self_signed_certificate_string(pem_data)


def get_private_key_pem_format_from_keyfile(filename):
    with open(filename, 'r') as f:
        key_data = f.read()
    private_key = RSA.import_key(key_data)
    return private_key.export_key()


def encrypt_rsa_pkcs1v15(public_key_pem, plaintext_bytes):
    # Get the public key in pem format
    rsa_public_key = RSA.import_key(public_key_pem)
    # Create a cipher object
    rsa_cipher = PKCS1_v1_5.new(rsa_public_key)
    # Encrypt the plaintext
    ciphertext_bytes = rsa_cipher.encrypt(plaintext_bytes)
    # Return the ciphertext
    return ciphertext_bytes


def decrypt_rsa_pkcs1v15(private_key_pem, ciphertext_bytes):
    # Get the private key in pem format
    rsa_private_key = RSA.import_key(private_key_pem)
    # Create a cipher object
    rsa_cipher = PKCS1_v1_5.new(rsa_private_key)
    # Decrypt the ciphertext
    plaintext_bytes = rsa_cipher.decrypt(ciphertext_bytes, None)
    # Return the plaintext
    return plaintext_bytes


def encode_bytes_to_base64_string(bytes):
    return base64.b64encode(bytes).decode('utf-8')


def decode_base64_string_to_bytes(base64_string):
    return base64.b64decode(base64_string)


def deterministically_combine_bytes(output_length=-1, bytes_list=[]):
    # Combine the byte list using SHA3-256
    # Create a SHA3-256 hasher object
    hasher = SHA3_256.new()
    # Update the hasher with the byte strings
    for bytes in bytes_list:
        hasher.update(bytes)
    # Return the hash digest
    combined_bytes = hasher.digest()
    # Return the first output_length bytes
    if output_length == -1:
        return combined_bytes
    return combined_bytes[:output_length]


def sign_with_rsa_pkcs1v15_and_sha3_256(private_key_pem, data_bytes):
    # Import the private key from pem format
    rsa_private_key = RSA.import_key(private_key_pem)
    # Sign the data
    signature = pkcs1_15.new(rsa_private_key).sign(SHA3_256.new(data_bytes))
    # Return the signature
    return signature


def verify_signature_with_rsa_pkcs1v15_and_sha3_256(public_key_pem, data_bytes, signature):
    # Import the public key from pem format
    rsa_public_key = RSA.import_key(public_key_pem)
    # Verify the signature
    try:
        pkcs1_15.new(rsa_public_key).verify(SHA3_256.new(data_bytes), signature)
        return True
    except (ValueError, TypeError):
        return False


# This function is used for testing the above functions
# To run this file, run the following command:
# python3 algorithms.py
if __name__ == "__main__":
    # Generate a random key
    aes_key = generate_aes_random_key()
    # Get the plaintext
    plaintext = "This is a test"
    # Convert the plaintext to bytes
    plaintext_bytes = bytes(plaintext, "utf-8")
    # Encrypt the plaintext
    ciphertext_bytes = encrypt_aes_ecb(aes_key, plaintext_bytes)
    # Decrypt the ciphertext
    decrypted_plaintext_bytes = decrypt_aes_ecb(aes_key, ciphertext_bytes)
    # Convert the decrypted plaintext to a string
    decrypted_plaintext = decrypted_plaintext_bytes.decode()
    
    print("AES ECB")
    print("-------")
    # Print plaintext
    print('plaintext:', plaintext)
    # Print aes_key
    print('aes_key:', aes_key)
    # Print the ciphertext
    print('ciphertext_bytes:', ciphertext_bytes)
    # Print the decrypted plaintext
    print('decrypted_plaintext:', decrypted_plaintext)

    
    print("\nRSA PKCS1v15")
    print("------------")
    # Get the public key in pem format of server-s
    public_key_pem = get_public_key_pem_format_from_self_signed_certificate_file('certs/server-s.crt')

    # Get the private key in pem format of server-s
    private_key_pem = get_private_key_pem_format_from_keyfile('certs/server-s.key')

    # Encrypt the plaintext
    ciphertext_bytes = encrypt_rsa_pkcs1v15(public_key_pem, plaintext_bytes)

    # Decrypt the ciphertext
    decrypted_plaintext_bytes = decrypt_rsa_pkcs1v15(private_key_pem, ciphertext_bytes)

    # Convert the decrypted plaintext to a string
    decrypted_plaintext = decrypted_plaintext_bytes.decode()

    # Print plaintext
    print('plaintext:', plaintext)

    # Print the public key
    print('public_key_pem:', public_key_pem)

    # Print the private key
    print('private_key_pem:', private_key_pem)

    # Print the ciphertext
    print('ciphertext_bytes:', ciphertext_bytes)

    # Print the decrypted plaintext
    print('decrypted_plaintext:', decrypted_plaintext)


    print("\nSHA3-256")
    print("--------")
    # Print the plaintext
    print('plaintext:', plaintext)
    # Print the hash of the plaintext, in hex format
    print('hash of plaintext:', hash_sha3_256(plaintext_bytes).hex())


    print("\nDeterministic Combination")
    print("-------------------------")
    random_bytes1 = generate_aes_random_key()
    random_bytes2 = generate_aes_random_key()
    random_bytes3 = generate_aes_random_key()

    # Print the random bytes
    print('random_bytes1 :', random_bytes1)
    print('random_bytes2 :', random_bytes2)
    print('random_bytes3 :', random_bytes3)

    # Combine the random bytes
    bytes_list = [random_bytes1, random_bytes2, random_bytes3]
    combined_bytes = deterministically_combine_bytes(16, bytes_list)

    # Print the combined bytes
    print('combined_bytes:', combined_bytes)


    print("\nBase64 Encoding")
    print("---------------")
    # Print the plaintext
    print('plaintext:', plaintext)

    # base64 encode the plaintext
    base64_string = encode_bytes_to_base64_string(plaintext_bytes)

    # Print the base64 encoding of the plaintext
    print('base64 encoding of plaintext:', base64_string)


    print("\nBase64 Decoding")
    print("---------------")
    # decode the base64 encoding of the plaintext
    decoded_bytes = decode_base64_string_to_bytes(base64_string)

    # Print the decoded bytes
    print('decoded_bytes:', decoded_bytes)

    # Convert the decoded bytes to a string
    decoded_string = decoded_bytes.decode()

    # Print the decoded string
    print('decoded_string:', decoded_string)


    print("\nRSA PKCS1v15 and SHA3-256 Signature")
    print("-----------------------------------")
    # Print the plaintext
    print('plaintext:', plaintext)

    # Sign the plaintext
    signature = sign_with_rsa_pkcs1v15_and_sha3_256(private_key_pem, plaintext_bytes)

    # Print the signature
    print('signature:', signature)

    # Verify the signature
    is_valid = verify_signature_with_rsa_pkcs1v15_and_sha3_256(public_key_pem, plaintext_bytes, signature)

    # Print whether the signature is valid
    print('is signature valid:', is_valid)
