import struct
import os
import time
import matplotlib.pyplot as plt
import psutil
import sys
import hmac
import hashlib

def rotate(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(x, a, b, c, d):
    x[b] ^= rotate((x[a] + x[d]) & 0xffffffff, 7)
    x[c] ^= rotate((x[b] + x[a]) & 0xffffffff, 9)
    x[d] ^= rotate((x[c] + x[b]) & 0xffffffff, 13)
    x[a] ^= rotate((x[d] + x[c]) & 0xffffffff, 18)

def salsa20_block(key, nonce, counter):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8L', key))
    nonce_words = list(struct.unpack('<2L', nonce))

    state = constants[:1] + key_words[:4] + constants[1:2] + nonce_words + [counter & 0xffffffff, (counter >> 32) & 0xffffffff] + key_words[4:] + constants[2:]

    working_state = state[:]
    for _ in range(10):  # 20 rounds = 10 double rounds
        # column rounds
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 5, 9, 13, 1)
        quarter_round(working_state, 10, 14, 2, 6)
        quarter_round(working_state, 15, 3, 7, 11)
        # row rounds
        quarter_round(working_state, 0, 1, 2, 3)
        quarter_round(working_state, 5, 6, 7, 4)
        quarter_round(working_state, 10, 11, 8, 9)
        quarter_round(working_state, 15, 12, 13, 14)

    result = [(x + y) & 0xffffffff for x, y in zip(state, working_state)]
    return struct.pack('<16L', *result)

def salsa20_encrypt(key, nonce, plaintext):
    block_size = 64
    keystream = b''
    for i in range((len(plaintext) + block_size - 1) // block_size):
        block = salsa20_block(key, nonce, i)
        keystream += block
    return bytes([p ^ k for p, k in zip(plaintext, keystream)])

# Function to compute HMAC-SHA256 for authentication
def compute_hmac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

# Function to measure memory usage during a process
def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024  # Memory in KB

# Function to process a file and measure encryption/decryption/auth times and memory
def analyze_file(filename, key, nonce):
    try:
        # Read the file
        with open(filename, 'rb') as f:
            plaintext = f.read()
        
        file_size = len(plaintext) / 1024  # Size in KB
        print(f"\nFile: {filename}")
        print(f"Size: {file_size:.2f} KB")

        # Measure memory before encryption
        mem_before = get_memory_usage()

        # Measure encryption time
        start_encrypt = time.time()
        ciphertext = salsa20_encrypt(key, nonce, plaintext)
        end_encrypt = time.time()
        encrypt_time = end_encrypt - start_encrypt

        # Measure authentication time during encryption (compute HMAC)
        start_auth_encrypt = time.time()
        auth_tag = compute_hmac(key, ciphertext)
        end_auth_encrypt = time.time()
        auth_time_encrypt = end_auth_encrypt - start_auth_encrypt

        # Measure memory after encryption
        mem_after_encrypt = get_memory_usage()

        # Measure decryption time (in Salsa20, decryption is the same as encryption)
        start_decrypt = time.time()
        decrypted = salsa20_encrypt(key, nonce, ciphertext)
        end_decrypt = time.time()
        decrypt_time = end_decrypt - start_decrypt

        # Measure authentication time during decryption (verify HMAC)
        start_auth_decrypt = time.time()
        computed_tag = compute_hmac(key, ciphertext)
        auth_verified = hmac.compare_digest(auth_tag, computed_tag)
        end_auth_decrypt = time.time()
        auth_time_decrypt = end_auth_decrypt - start_auth_decrypt

        # Measure memory after decryption
        mem_after_decrypt = get_memory_usage()

        # Calculate average memory usage and authentication time
        avg_memory = (mem_after_encrypt + mem_after_decrypt) / 2
        avg_auth_time = (auth_time_encrypt + auth_time_decrypt) / 2

        # Print results
        print(f"Encryption Time: {encrypt_time:.6f} seconds")
        print(f"Decryption Time: {decrypt_time:.6f} seconds")
        print(f"Average Authentication Time: {avg_auth_time:.6f} seconds")
        print(f"Average Memory Usage: {avg_memory:.2f} KB")

        # Verify decryption and authentication
        assert plaintext == decrypted, "Decryption failed!"
        assert auth_verified, "Authentication verification failed!"

        return file_size, encrypt_time, decrypt_time, avg_auth_time, avg_memory

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        return None, None, None, None, None
    except Exception as e:
        print(f"Error processing file '{filename}': {e}")
        return None, None, None, None, None

# Main execution
if __name__ == "__main__":
    key = b"This is a 32-byte Salsa20 key!!!"[:32]
    nonce = b"8byteNON"[:8]

    # List of test files (create dummy files or use existing ones)
    sizes = [10, 50, 100, 150, 200]  # Sizes in KB
    filenames = [f"test_file_{size}KB.bin" for size in sizes]

    # Create test files if they don't exist
    for size, filename in zip(sizes, filenames):
        if not os.path.exists(filename):
            with open(filename, 'wb') as f:
                f.write(os.urandom(size * 1024))

    # Lists to store results for plotting
    file_sizes = []
    encrypt_times = []
    decrypt_times = []
    auth_times = []
    avg_memories = []

    # Analyze each file
    for filename in filenames:
        size, enc_time, dec_time, avg_auth, avg_mem = analyze_file(filename, key, nonce)
        if size is not None:
            file_sizes.append(size)
            encrypt_times.append(enc_time)
            decrypt_times.append(dec_time)
            auth_times.append(avg_auth)
            avg_memories.append(avg_mem)

    # Plot encryption, decryption, and authentication times
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 3, 1)
    plt.plot(file_sizes, encrypt_times, marker='o', label='Encryption Time')
    plt.plot(file_sizes, decrypt_times, marker='s', label='Decryption Time')
    plt.title("Salsa20 Encryption/Decryption Time")
    plt.xlabel("Data Size (KB)")
    plt.ylabel("Time (seconds)")
    plt.legend()
    plt.grid(True)

    # Plot average authentication time
    plt.subplot(1, 3, 2)
    plt.plot(file_sizes, auth_times, marker='^', color='red', label='Avg Authentication Time')
    plt.title("Salsa20 Avg Authentication Time")
    plt.xlabel("Data Size (KB)")
    plt.ylabel("Time (seconds)")
    plt.legend()
    plt.grid(True)

    # Plot average memory usage
    plt.subplot(1, 3, 3)
    plt.plot(file_sizes, avg_memories, marker='^', color='green', label='Avg Memory Usage')
    plt.title("Salsa20 Average Memory Usage")
    plt.xlabel("Data Size (KB)")
    plt.ylabel("Memory (KB)")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.show()
main()