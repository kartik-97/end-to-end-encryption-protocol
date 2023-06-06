# End to End Encryption Protocol
This project demonstrates the implementation of an end-to-end encryption protocol.

The following was achieved:

- Ensured that all client communications are facilitated exclusively via 
the server, prohibiting direct inter-client exchanges.

- Implemented mutual authentication between clients and the server 
for improved security.

- Designed the system in such a way that the server remains unaware 
of the established session key, enhancing privacy.

- Utilized RSA encryption algorithm to securely exchange random 
nonces between clients, which are subsequently used to generate a 
mutually agreed session key to be used with AES algorithm.

## Please read ProjectDocumentation.pdf
It contains explanation of the e2e protocol

## Please read installation.txt
It contains installation instructions
