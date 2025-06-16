import socket

key = b'16_byte_key_1234'
iv = b'12_byte_iv_1'

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("127.0.0.1", 12345))

try:
    command = "automate"
    print(f"Client: Sending command '{command}' to server...")
    client_socket.send(command.encode())
    response = client_socket.recv(4096).decode()
    print("Server response:\n" + response)
    with open('client_results.txt', 'w') as f:
        f.write(response)
    print("Results saved to client_results.txt")

except Exception as e:
    print(f"Error: {e}")

finally:
    client_socket.close()
    print("Connection closed.")