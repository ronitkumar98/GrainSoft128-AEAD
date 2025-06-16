# server.py
import socket
import json
import time
import statistics
from Trivium import Trivium

def start_server(host='localhost', port=12345, iterations=100):
    # Initialize Trivium
    key = [1] * 80
    iv = [0] * 80
    cipher = Trivium(key, iv)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")
    
    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address}")
        
        # Receive file size
        file_size = int(client_socket.recv(1024).decode())
        client_socket.send(b"Ready to receive")
        
        # Receive file data
        data = b""
        while len(data) < file_size:
            chunk = client_socket.recv(min(4096, file_size - len(data)))
            if not chunk:
                break
            data += chunk
            
        # Perform multiple encryption iterations
        encryption_times = []
        for i in range(iterations):
            start_time = time.perf_counter()  # Using perf_counter for higher precision
            encrypted_data = cipher.encrypt(data)
            encryption_time = time.perf_counter() - start_time
            encryption_times.append(encryption_time)
            
            if (i + 1) % 10 == 0:
                print(f"Completed {i + 1}/{iterations} iterations for file size {file_size} bytes")
        
        # Calculate statistics
        stats = {
            'mean': statistics.mean(encryption_times),
            'median': statistics.median(encryption_times),
            'std_dev': statistics.stdev(encryption_times),
            'min': min(encryption_times),
            'max': max(encryption_times),
            'iterations': iterations
        }
        
        # Send statistics to client
        client_socket.send(json.dumps(stats).encode())
        client_socket.close()

if __name__ == "__main__":
    start_server()
