import socket
from grain128AED import Grain128AEAD

# Initialize Grain128AEAD
key = b'16_byte_key_1234'
iv = b'12_byte_iv_1'
grain = Grain128AEAD(key, iv)

# Server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("127.0.0.1", 12345))
server_socket.listen(1)
print("Server is listening...")

conn, addr = server_socket.accept()
print(f"Connection established with {addr}")

while True:
    # Receive and decrypt client's message
    encrypted_message = conn.recv(1024)
    if not encrypted_message:
        break

    associated_data = bytearray("Some associated data", 'utf-8')
    decrypted_message = grain.decrypt(encrypted_message, associated_data)
    print(f"Client: {decrypted_message.decode()}")

    # Encrypt and send response
    response = "Message received!"
    plaintext_response = bytearray(response, 'utf-8')
    encrypted_response = grain.encrypt(plaintext_response, associated_data)
    conn.send(encrypted_response)

conn.close()
server_socket.close()
