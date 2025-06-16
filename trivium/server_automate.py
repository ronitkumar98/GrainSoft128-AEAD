# server.py
import socket
import os
import json
import time
from Trivium import Trivium

def start_server(host='localhost', port=12345):
    # Initialize Trivium with key and IV (should be properly generated in production)
    key = [1] * 80  # 80-bit key
    iv = [0] * 80   # 80-bit IV
    cipher = Trivium(key, iv)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")
    
    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address}")
        
        # Receive file size from client
        file_size = int(client_socket.recv(1024).decode())
        client_socket.send(b"Ready to receive")
        
        # Receive file data
        data = b""
        while len(data) < file_size:
            chunk = client_socket.recv(min(4096, file_size - len(data)))
            if not chunk:
                break
            data += chunk
        
        # Encrypt and measure time
        start_time = time.time()
        encrypted_data = cipher.encrypt(data)
        encryption_time = time.time() - start_time
        
        # Send encryption time back to client
        client_socket.send(str(encryption_time).encode())
        client_socket.close()

if __name__ == "__main__":
    start_server()

