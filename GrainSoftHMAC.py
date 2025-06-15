import hmac
import hashlib
import os
import time
import tracemalloc

class GrainSoft128AEAD:
    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits)")
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes (96 bits)")
        self.key = key
        self.iv = iv
        self.mask = (1 << 128) - 1
        self.lfsr = 0
        self.nfsr = 0
        self.ks = []
        self._initialize()

    def _initialize(self):
        self.lfsr = 0
        self.nfsr = 0
        # Load IV into LFSR
        for i in range(96):
            bit = (self.iv[i // 8] >> (7 - (i % 8))) & 1
            self.lfsr |= (bit << i)
        self.lfsr |= ((1 << 32) - 1) << 96  # Set bits 96-127 to 1
        # Load key into NFSR
        for i in range(128):
            bit = (self.key[i // 8] >> (7 - (i % 8))) & 1
            self.nfsr |= (bit << i)
        for _ in range(256):
            ks_bit = self._clock()
            self.lfsr = ((self.lfsr << 1) | ks_bit) & self.mask
            self.nfsr = ((self.nfsr << 1) | ks_bit) & self.mask

    def reset(self):
        self.ks = []
        self._initialize()

    def _clock(self):
        # LFSR feedback
        lfsr_0 = self.lfsr & 1
        lfsr_fb = (
            lfsr_0 ^
            ((self.lfsr >> 7) & 1) ^
            ((self.lfsr >> 20) & 1) ^
            ((self.lfsr >> 42) & 1) ^
            ((self.lfsr >> 57) & 1) ^
            ((self.lfsr >> 91) & 1)
        ) & 1

        # NFSR feedback
        nfsr_0 = self.nfsr & 1
        nfsr_fb = (
            nfsr_0 ^
            ((self.nfsr >> 63) & 1) ^
            ((self.nfsr >> 95) & 1) ^
            (((self.nfsr >> 11) & 1) & ((self.nfsr >> 13) & 1)) ^
            (((self.nfsr >> 23) & 1) & ((self.nfsr >> 25) & 1)) ^
            (((self.nfsr >> 47) & 1) & ((self.nfsr >> 49) & 1)) ^
            lfsr_0
        ) & 1

        self.lfsr = ((self.lfsr >> 1) | (lfsr_fb << 127)) & self.mask
        self.nfsr = ((self.nfsr >> 1) | (nfsr_fb << 127)) & self.mask

        # Output function h
        h = (
            ((self.lfsr >> 3) & 1) ^
            ((self.nfsr >> 2) & 1) ^
            (((self.lfsr >> 64) & 1) & ((self.nfsr >> 63) & 1)) ^
            ((self.nfsr >> 25) & 1) ^
            ((self.nfsr >> 46) & 1) ^
            ((self.lfsr >> 93) & 1)
        ) & 1

        ks_bit = (h ^ nfsr_0) & 1
        self.ks.append(ks_bit)
        return ks_bit

    def _generate_keystream(self, length):
        stream = bytearray()
        for _ in range(length):
            byte = 0
            for _ in range(8):
                byte = (byte << 1) | self._clock()
            stream.append(byte)
        return bytes(stream)

    def _get_hmac(self, ciphertext: bytes, hmac_key: bytes, associated_data: bytes = b''):
        return hmac.new(hmac_key, associated_data + ciphertext, hashlib.sha256).digest()

    def encrypt_and_tag(self, plaintext: bytes, hmac_key: bytes, associated_data: bytes = b''):
        self.reset()
        keystream = self._generate_keystream(len(plaintext))
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
        tag = self._get_hmac(ciphertext, hmac_key, associated_data)
        return ciphertext, tag

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, hmac_key: bytes, associated_data: bytes = b''):
        expected_tag = self._get_hmac(ciphertext, hmac_key, associated_data)
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Authentication failed: HMAC tag mismatch.")
        self.reset()
        keystream = self._generate_keystream(len(ciphertext))
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        return plaintext


if __name__ == "__main__":
    key = b'16_byte_key_1234'
    iv = b'12_byte_iv_1'
    hmac_key = b'32_byte_hmac_key_12345678901234'
    associated_data = b"benchmark|round=1"
    folder_path='./../generate_files'
    print(f"{'File':<15}{'Size (KB)':<10}{'Avg Time (ms)':<15}{'Peak Mem (KB)':<15}")
    print("-" * 55)

    for filename in sorted(os.listdir(folder_path)):
        file_path = os.path.join(folder_path, filename)

        if not os.path.isfile(file_path):
            continue

        file_size_kb = os.path.getsize(file_path) / 1024
        total_time = 0
        peak_memory = 0

        for _ in range(0,1):
            with open(file_path, "rb") as f:
                data = f.read()

            cipher = GrainSoft128AEAD(key, iv)

            tracemalloc.start()
            start = time.perf_counter()
            ciphertext, tag = cipher.encrypt_and_tag(data, hmac_key, associated_data)
            end = time.perf_counter()
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            total_time += (end - start) * 1000  # ms
            peak_memory = max(peak_memory, peak / 1024)  # KB

        avg_time = total_time

        print(f"{filename:<15}{file_size_kb:<10.1f}{avg_time:<15.2f}{peak_memory:<15.2f}")
