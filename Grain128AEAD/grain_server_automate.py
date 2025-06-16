import socket
import threading
import os
import time
import psutil
import csv
from pathlib import Path
from grain128AED import Grain128AEAD

class GrainAEADServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.key = b'16_byte_key_1234'
        self.iv = b'12_byte_iv_1'
        self.ad = b'Some associated data'
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

    def handle_client(self, conn, addr):
        print(f"Connected to {addr}")
        while True:
            try:
                data = conn.recv(1024).decode()
                if not data:
                    break
                cmd, *args = data.split('|')
                print(f"Received command: {cmd} from {addr}")

                if cmd.lower() == 'automate':
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
                            dec_times = []
                            auth_times = []
                            mem_deltas = []
                            num_iterations = 3
                            for i in range(num_iterations):
                                if i % 2 == 0:
                                    print(f"Iteration {i}/{num_iterations} for {file_path.name}")
                                cipher = Grain128AEAD(self.key, self.iv)
                                mem_before = psutil.Process().memory_info().rss / 1024
                                start_time = time.perf_counter()
                                ciphertext, _ = cipher.encrypt(data, self.ad)
                                end_time = time.perf_counter()
                                enc_times.append((end_time - start_time) * 1000)
                                cipher = Grain128AEAD(self.key, self.iv)
                                start_time = time.perf_counter()
                                decrypted, dec_tag = cipher.decrypt(ciphertext, self.ad)
                                end_time = time.perf_counter()
                                dec_times.append((end_time - start_time) * 1000)
                                cipher = Grain128AEAD(self.key, self.iv)
                                start_auth = time.perf_counter()
                                auth_tag = cipher.get_tag(ciphertext, self.ad)
                                end_auth = time.perf_counter()
                                auth_times.append((end_auth - start_auth) * 1000)
                                mem_after = psutil.Process().memory_info().rss / 1024
                                mem_deltas.append(mem_after - mem_before)
                            verified = (decrypted == data and auth_tag == dec_tag)
                            if verified:
                                avg_enc_time = sum(enc_times) / len(enc_times)
                                avg_dec_time = sum(dec_times) / len(dec_times)
                                avg_auth_time = sum(auth_times) / len(auth_times)
                                avg_mem_delta = sum(mem_deltas) / len(mem_deltas)
                                results.append(
                                    f"File: {file_path.name}, "
                                    f"Size: {len(data) / 1024:.2f} KB, "
                                    f"Avg Enc Time: {avg_enc_time:.2f} ms, "
                                    f"Avg Dec Time: {avg_dec_time:.2f} ms, "
                                    f"Avg Auth Time: {avg_auth_time:.2f} ms, "
                                    f"Avg Memory Delta: {avg_mem_delta:.2f} KB"
                                )
                                csv_data.append({
                                    'File': file_path.name,
                                    'Size_KB': len(data) / 1024,
                                    'Avg_Enc_Time_ms': avg_enc_time,
                                    'Avg_Dec_Time_ms': avg_dec_time,
                                    'Avg_Auth_Time_ms': avg_auth_time,
                                    'Avg_Memory_KB': avg_mem_delta
                                })
                            else:
                                results.append(f"File: {file_path.name}, Error: Decryption or Auth failed")
                            print(f"Finished processing {file_path.name}")
                        except Exception as e:
                            results.append(f"File: {file_path.name}, Error: {str(e)}")
                            print(f"Error processing {file_path.name}: {e}")
                    csv_file = Path('benchmark_results.csv')
                    try:
                        with open(csv_file, 'w', newline='') as f:
                            writer = csv.DictWriter(f, fieldnames=['File', 'Size_KB', 'Avg_Enc_Time_ms', 'Avg_Dec_Time_ms', 'Avg_Auth_Time_ms', 'Avg_Memory_KB'])
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

                else:
                    conn.send("Error: Invalid command".encode())

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
        server = GrainAEADServer()
        server.start()
    except Exception as e:
        print(f"Server failed to start: {e}")