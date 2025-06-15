import socket
import threading
import os
import time
import psutil
import hmac
import csv
from pathlib import Path
from grainsoft_v3 import GrainSoft128AEAD

class GrainSoftServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.key = b'16_byte_key_1234'  # 16 bytes
        self.iv = b'12_byte_iv_1'     # 12 bytes
        self.hmac_key = b'32_byte_hmac_key_12345678901234'
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            print(f"Attempting to bind to {self.host}:{self.port}")
            self.sock.bind((self.host, self.port))
            print("Bind successful")
        except Exception as e:
            print(f"Failed to bind to {self.host}:{self.port}: {e}")
            self.sock.close()
            raise
        self.sock.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

    def handle_client(self, conn, addr):
        print(f"Connected to {addr}")
        cipher = GrainSoft128AEAD(self.key, self.iv)
        while True:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break
                cmd, *args = data.split('|')
                print(f"Received command: {cmd} from {addr}")
                
                if cmd == 'encrypt':
                    plaintext = args[0].encode()
                    start_time = time.perf_counter()
                    cipher = GrainSoft128AEAD(self.key, self.iv)
                    ciphertext, tag = cipher.encrypt_and_tag(plaintext, self.hmac_key)
                    end_time = time.perf_counter()
                    mem_usage = psutil.Process().memory_info().rss / 1024
                    response = (
                        f"Ciphertext: {ciphertext.hex()}|"
                        f"Tag: {tag.hex()}|"
                        f"Time: {(end_time - start_time) * 1000:.2f} ms|"
                        f"Memory: {mem_usage:.2f} KB"
                    )
                    conn.send(response.encode())

                elif cmd == 'decrypt':
                    ciphertext = bytes.fromhex(args[0])
                    client_tag = bytes.fromhex(args[1])
                    start_time = time.perf_counter()
                    cipher = GrainSoft128AEAD(self.key, self.iv)
                    try:
                        plaintext = cipher.decrypt_and_verify(ciphertext, client_tag, self.hmac_key)
                        end_time = time.perf_counter()
                        mem_usage = psutil.Process().memory_info().rss / 1024
                        response = (
                            f"Plaintext: {plaintext.decode()}|"
                            f"Time: {(end_time - start_time) * 1000:.2f} ms|"
                            f"Memory: {mem_usage:.2f} KB"
                        )
                    except ValueError as e:
                        response = f"Error: {str(e)}"
                    conn.send(response.encode())

                elif cmd == 'automate':
                    print(f"Starting automate for {addr}")
                    results = []
                    csv_data = []
                    folder = Path('../generate_files')
                    if not folder.exists():
                        conn.send("Error: generate_files folder not found".encode())
                        break
                    for file_path in folder.glob('*'):
                        print(f"Processing file: {file_path.name}")
                        try:
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            print(f"Read {len(data)} bytes from {file_path.name}")
                            enc_times = []
                            mem_usages = []
                            num_iterations = 10
                            for i in range(num_iterations):
                                if i % 2 == 0:
                                    print(f"Iteration {i}/{num_iterations} for {file_path.name}")
                                start_time = time.perf_counter()
                                cipher = GrainSoft128AEAD(self.key, self.iv)
                                ciphertext, tag = cipher.encrypt_and_tag(data, self.hmac_key)
                                end_time = time.perf_counter()
                                mem_usage = psutil.Process().memory_info().rss / 1024
                                enc_times.append((end_time - start_time) * 1000)
                                mem_usages.append(mem_usage)
                            print(f"Verifying decryption for {file_path.name}")
                            cipher = GrainSoft128AEAD(self.key, self.iv)
                            decrypted = cipher.decrypt_and_verify(ciphertext, tag, self.hmac_key)
                            if decrypted == data:
                                avg_enc_time = sum(enc_times) / len(enc_times)
                                avg_mem_usage = sum(mem_usages) / len(mem_usages)
                                results.append(
                                    f"File: {file_path.name}, "
                                    f"Size: {len(data) / 1024:.2f} KB, "
                                    f"Avg Enc Time: {avg_enc_time:.2f} ms, "
                                    f"Avg Memory: {avg_mem_usage:.2f} KB"
                                )
                                csv_data.append({
                                    'File': file_path.name,
                                    'Size_KB': len(data) / 1024,
                                    'Avg_Enc_Time_ms': avg_enc_time,
                                    'Avg_Memory_KB': avg_mem_usage
                                })
                            else:
                                results.append(f"File: {file_path.name}, Error: Decryption failed")
                            print(f"Finished processing {file_path.name}")
                        except Exception as e:
                            results.append(f"File: {file_path.name}, Error: {str(e)}")
                            print(f"Error processing {file_path.name}: {e}")
                    csv_file = Path('benchmark_results.csv')
                    try:
                        with open(csv_file, 'w', newline='') as f:
                            writer = csv.DictWriter(f, fieldnames=['File', 'Size_KB', 'Avg_Enc_Time_ms', 'Avg_Memory_KB'])
                            writer.writeheader()
                            writer.writerows(csv_data)
                        print(f"Saved results to {csv_file}")
                    except Exception as e:
                        results.append(f"Error saving CSV: {str(e)}")
                        print(f"Error saving CSV: {e}")
                    response = '\n'.join(results)
                    print(f"Sending automate results: {len(response)} bytes")
                    conn.send(response.encode())
                    print(f"Automate completed for {addr}")

            except Exception as e:
                error_msg = f"Error: {str(e)}"
                print(f"Error handling command from {addr}: {e}")
                conn.send(error_msg.encode())
                break
        conn.close()
        print(f"Disconnected from {addr}")

    def start(self):
        try:
            while True:
                conn, addr = self.sock.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
        except KeyboardInterrupt:
            print("Shutting down server...")
            self.sock.close()

if __name__ == "__main__":
    try:
        server = GrainSoftServer()
        server.start()
    except Exception as e:
        print(f"Server failed to start: {e}")