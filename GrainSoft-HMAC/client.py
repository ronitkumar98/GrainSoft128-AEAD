import socket
from grainsoft_v3 import GrainSoft128AEAD

class GrainSoftClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.key = b'16_byte_key_1234'  # 16 bytes
        self.iv = b'12_byte_iv_1'      # 12 bytes
        print(f"IV: {self.iv}, Length: {len(self.iv)}")
        self.hmac_key = b'32_byte_hmac_key_12345678901234'
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = GrainSoft128AEAD(self.key, self.iv)

    def connect(self):
        try:
            self.sock.connect((self.host, self.port))
            print(f"Connected to {self.host}:{self.port}")
        except Exception as e:
            print(f"Failed to connect: {e}")
            raise

    def send_command(self, cmd):
        try:
            print(f"Sending command: {cmd}")
            self.sock.send(cmd.encode())
            response = self.sock.recv(16384).decode()
            print("Server response:")
            print(response)
        except Exception as e:
            print(f"Error sending/receiving: {e}")
            raise

    def run(self):
        try:
            self.connect()
            while True:
                print("\nGrainSoft128 Client Menu:")
                print("1. Encrypt message")
                print("2. Decrypt ciphertext")
                print("3. Run automation benchmark")
                print("4. Exit")
                choice = input("Select option (1-4): ")

                if choice == '1':
                    message = input("Enter message to encrypt: ")
                    self.send_command(f"encrypt|{message}")

                elif choice == '2':
                    ciphertext = input("Enter ciphertext (hex): ")
                    tag = input("Enter Tag (hex): ")
                    self.send_command(f"decrypt|{ciphertext}|{tag}")

                elif choice == '3':
                    print("Running automate benchmark...")
                    self.send_command("automate")

                elif choice == '4':
                    print("Exiting...")
                    self.sock.close()
                    break

                else:
                    print("Invalid choice. Try again.")
        except Exception as e:
            print(f"Client error: {e}")
            self.sock.close()

if __name__ == "__main__":
    client = GrainSoftClient()
    client.run()