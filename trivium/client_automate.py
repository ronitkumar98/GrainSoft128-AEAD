# client.py
import socket
import os
import json
import time

def send_file(filename, host='localhost', port=12345):
    with open(filename, 'rb') as f:
        data = f.read()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Send file size first
    client_socket.send(str(len(data)).encode())
    client_socket.recv(1024)  # Wait for server ready signal
    
    # Send file data
    client_socket.send(data)
    
    # Receive encryption time
    encryption_time = float(client_socket.recv(1024).decode())
    client_socket.close()
    
    return len(data), encryption_time

def process_directory(directory_path):
    results = []
    
    for filename in os.listdir(directory_path):
        if os.path.isfile(os.path.join(directory_path, filename)):
            file_path = os.path.join(directory_path, filename)
            file_size, encryption_time = send_file(file_path)
            results.append({
                'filename': filename,
                'size_bytes': file_size,
                'encryption_time': encryption_time
            })
    
    # Sort results by file size
    results.sort(key=lambda x: x['size_bytes'])
    
    # Print results
    print("\nEncryption Time Results:")
    print("-" * 60)
    print(f"{'Filename':<20} {'Size (KB)':<15} {'Time (seconds)':<15}")
    print("-" * 60)
    for result in results:
        print(f"{result['filename']:<20} {result['size_bytes']/1024:<15.2f} {result['encryption_time']:<15.6f}")
    
    # Save results to JSON file
    with open('encryption_results.json', 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    directory_path = "./../generate_files"  # Change this to your directory path
    process_directory(directory_path)