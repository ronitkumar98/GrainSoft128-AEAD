import struct
import os
import time
import matplotlib.pyplot as plt

def rotate(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotate(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotate(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = rotate(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = rotate(state[b], 7)

def chacha20_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8L', key))
    nonce_words = list(struct.unpack('<3L', nonce))
    state = constants + key_words + [counter] + nonce_words
    working_state = list(state)

    for _ in range(10):
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

    output = [(x + y) & 0xffffffff for x, y in zip(working_state, state)]
    return struct.pack('<16L', *output)

def chacha20_encrypt(key, counter, nonce, plaintext):
    keystream = b''
    for block_counter in range((len(plaintext) + 63) // 64):
        block = chacha20_block(key, counter + block_counter, nonce)
        keystream += block
    return bytes([p ^ k for p, k in zip(plaintext, keystream)])

if __name__ == "__main__":
    key = b"this is 32-byte key for ChaCha20!!"[:32]
    nonce = b"123456789012"[:12]
    counter = 1

    sizes = [10,50,100,150,200]  # sizes in KB
    times = []

    for size in sizes:
        data = os.urandom(size * 1024)
        start = time.time()
        chacha20_encrypt(key, counter, nonce, data)
        end = time.time()
        elapsed = end - start
        times.append(elapsed)
        print(f"{size} KB: {elapsed:.6f} seconds")

    plt.plot(sizes, times, marker='o')
    plt.title("ChaCha20 Encryption Time")
    plt.xlabel("Data Size (KB)")
    plt.ylabel("Time (seconds)")
    plt.grid(True)
    plt.show()
    
main()