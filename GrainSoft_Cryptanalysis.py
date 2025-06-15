import os
import time
import numpy as np
from scipy import stats
from grainsoft_v3 import GrainSoft128AEAD

def frequency_test(bits):
    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    s = abs(ones - zeros) / np.sqrt(n)
    p_value = stats.norm.sf(s) * 2  # Two-tailed test
    return p_value

def runs_test(bits):
    n = len(bits)
    pi = sum(bits) / n
    v = 1 + sum(1 for i in range(n-1) if bits[i] != bits[i+1])
    p_value = stats.norm.sf(abs(v - 2 * n * pi * (1 - pi)) / (2 * np.sqrt(n) * pi * (1 - pi))) * 2
    return p_value

def generate_keystream(cipher, length):
    keystream = cipher._generate_keystream(length)
    bits = []
    for byte in keystream:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits

def differential_analysis(key, iv, length=1000):
    cipher1 = GrainSoft128AEAD(key, iv)
    iv2 = bytearray(iv)
    iv2[0] ^= 1  # Flip first bit
    cipher2 = GrainSoft128AEAD(key, bytes(iv2))
    
    ks1 = generate_keystream(cipher1, length)
    ks2 = generate_keystream(cipher2, length)
    diff = [a ^ b for a, b in zip(ks1, ks2)]
    hamming_weight = sum(diff)
    return hamming_weight, len(diff)

def linear_approximation_data(key, iv, length=1000):
    cipher = GrainSoft128AEAD(key, iv)
    bits = generate_keystream(cipher, length)
    with open("keystream_bits.txt", "w") as f:
        f.write("".join(map(str, bits)))
    return bits

if __name__ == "__main__":
    key = os.urandom(16)
    iv = os.urandom(12)
    mac_key = os.urandom(16)
    
    print("=== GrainSoft128AEAD Cryptanalysis ===")
    
    # Randomness Tests
    print("\n[1] Randomness Tests:")
    cipher = GrainSoft128AEAD(key, iv)
    bits = generate_keystream(cipher, 100000)  # 100KB
    freq_p = frequency_test(bits)
    runs_p = runs_test(bits)
    print(f"  → Frequency Test p-value: {freq_p:.6f} {'(Pass)' if freq_p >= 0.01 else '(Fail)'}")
    print(f"  → Runs Test p-value:      {runs_p:.6f} {'(Pass)' if runs_p >= 0.01 else '(Fail)'}")
    
    # Differential Analysis
    print("\n[2] Differential Analysis:")
    hamming_weight, total_bits = differential_analysis(key, iv)
    print(f"  → Hamming weight of keystream difference: {hamming_weight}/{total_bits} ({hamming_weight/total_bits:.2%})")
    
    # Linear Approximation Data
    print("\n[3] Linear Approximation Data:")
    _ = linear_approximation_data(key, iv)
    print("  → Keystream bits saved to keystream_bits.txt for SAGE analysis")

    # Sample Encryption-Decryption
    print("\n[4] Encryption-Decryption Sample:")
    msg = b"This is a secret message"
    cipher = GrainSoft128AEAD(key, iv)
    ciphertext, tag = cipher.encrypt_and_tag(msg, mac_key)
    print(f"  → Ciphertext: {ciphertext.hex()}")
    print(f"  → Tag:        {tag.hex()}")

    # Reinitialize to test decryption
    cipher = GrainSoft128AEAD(key, iv)
    try:
        decrypted = cipher.decrypt_and_verify(ciphertext, tag, mac_key)
        print(f"  → Decrypted:  {decrypted.decode()}")
    except ValueError:
        print(" MAC verification failed!")

    # Performance Benchmark
    print("\n[5] Performance Benchmark:")
    cipher = GrainSoft128AEAD(key, iv)
    data = os.urandom(10000)  # 10KB test

    start = time.perf_counter()
    ciphertext, tag = cipher.encrypt_and_tag(data, mac_key)
    enc_time = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    cipher = GrainSoft128AEAD(key, iv)
    try:
        cipher.decrypt_and_verify(ciphertext, tag, mac_key)
    except ValueError:
        pass
    dec_time = (time.perf_counter() - start) * 1000

    print(f"  → Encryption + Tagging Time (10KB):   {enc_time:.2f} ms")
    print(f"  → Decryption + Verification Time:     {dec_time:.2f} ms")
