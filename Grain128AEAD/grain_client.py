import socket
from grain128AED import Grain128AEAD

# Initialize Grain128AEAD
key = b'16_byte_key_1234'
iv = b'12_byte_iv_1'
grain = Grain128AEAD(key, iv)

# Client socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

while True:
    message = input("Client: ")
    if message.lower() == "exit":
        break

    # Encrypt the message
    plaintext = bytearray(message, 'utf-8')
    associated_data = bytearray("Some associated data", 'utf-8')
    ciphertext = grain.encrypt(plaintext, associated_data)

    # Send ciphertext
    client_socket.send(ciphertext)

    # Receive and decrypt server's response
    encrypted_response = client_socket.recv(1024)
    decrypted_response = grain.decrypt(encrypted_response, associated_data)
    print(f"Server: {decrypted_response.decode()}")

client_socket.close()
