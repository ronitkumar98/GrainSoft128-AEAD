import os
import time
import tracemalloc
import hmac
from cryptography.hazmat.primitives import poly1305
from cryptography.exceptions import InvalidTag

class GrainSoft128AEAD:
    """Lightweight stream cipher with AEAD support inspired by Grain-128a.
    
    Args:
        key (bytes): 16-byte encryption key (128 bits).
        iv (bytes): 12-byte initialization vector (96 bits).
    
    Warning:
        IV must be unique for each encryption under the same key.
        Experimental cipher; requires cryptanalysis before production use.
    """
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
        self.used_ivs = set()  # Track used IVs (optional)
        self._initialize()

    def _initialize(self):
        """Initialize LFSR and NFSR with key and IV."""
        self.lfsr = 0
        self.nfsr = 0
        # Load IV into LFSR
        for i in range(96):
            bit = (self.iv[i // 8] >> (7 - (i % 8))) & 1
            self.lfsr |= (bit << i)
        # Randomize LFSR bits 96-127 with key
        for i in range(96, 128):
            bit = (self.key[(i - 96) // 8] >> (7 - ((i - 96) % 8))) & 1
            self.lfsr |= (bit << i)
        # Load key into NFSR
        for i in range(128):
            bit = (self.key[i // 8] >> (7 - (i % 8))) & 1
            self.nfsr |= (bit << i)
        # Run initialization for 256 clocks
        for i in range(256):
            ks_bit = self._clock()
            key_bit = (self.key[(i // 8) % 16] >> (7 - (i % 8))) & 1
            self.lfsr = ((self.lfsr << 1) | (ks_bit ^ key_bit)) & self.mask
            self.nfsr = ((self.nfsr << 1) | (ks_bit ^ key_bit)) & self.mask

    def reset(self):
        """Reset cipher state and reinitialize."""
        self._initialize()

    def _clock(self):
        """Update LFSR and NFSR, return keystream bit."""
        lfsr_0 = self.lfsr & 1
        lfsr_fb = (
            lfsr_0 ^
            ((self.lfsr >> 7) & 1) ^
            ((self.lfsr >> 20) & 1) ^
            ((self.lfsr >> 42) & 1) ^
            ((self.lfsr >> 57) & 1) ^
            ((self.lfsr >> 91) & 1)
        ) & 1

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

        h = (
            ((self.lfsr >> 3) & 1) ^
            ((self.nfsr >> 2) & 1) ^
            (((self.lfsr >> 64) & 1) & ((self.nfsr >> 63) & 1)) ^
            ((self.nfsr >> 25) & 1) ^
            ((self.nfsr >> 46) & 1) ^
            ((self.lfsr >> 93) & 1) ^
            (((self.lfsr >> 10) & 1) & ((self.nfsr >> 20) & 1))
        ) & 1

        return (h ^ nfsr_0) & 1

    def _generate_keystream(self, length):
        """Generate keystream bytes."""
        stream = bytearray(length)
        for i in range(length):
            byte = 0
            for j in range(8):
                byte |= self._clock() << (7 - j)
            stream[i] = byte
        return bytes(stream)

    def _get_poly1305(self, ciphertext: bytes, mac_key: bytes, associated_data: bytes = b''):
        """Generate Poly1305 tag for AEAD."""
        if len(mac_key) != 32:
            raise ValueError("Poly1305 key must be 32 bytes")
        if len(ciphertext) == 0 and len(associated_data) == 0:
            raise ValueError("Ciphertext and associated data cannot both be empty")
        mac = poly1305.Poly1305(mac_key)
        mac.update(associated_data + ciphertext)
        return mac.finalize()

    def encrypt_and_tag(self, plaintext: bytes, mac_key: bytes, associated_data: bytes = b'', chunk_size=1024):
        """Encrypt plaintext and generate authentication tag."""
        if self.iv in self.used_ivs:
            import warnings
            warnings.warn("IV reuse detected; this is insecure!")
        self.used_ivs.add(self.iv)
        self.reset()
        ciphertext = bytearray()
        for i in range(0, len(plaintext), chunk_size):
            chunk = plaintext[i:i + chunk_size]
            keystream = self._generate_keystream(len(chunk))
            ciphertext.extend(p ^ k for p, k in zip(chunk, keystream))
        tag = self._get_poly1305(bytes(ciphertext), mac_key, associated_data)
        return bytes(ciphertext), tag

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, mac_key: bytes, associated_data: bytes = b''):
        """Decrypt ciphertext and verify tag."""
        expected_tag = self._get_poly1305(ciphertext, mac_key, associated_data)
        if not hmac.compare_digest(tag, expected_tag):
            raise InvalidTag("Authentication failed: Poly1305 tag mismatch")
        self.reset()
        keystream = self._generate_keystream(len(ciphertext))
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        return plaintext


if __name__ == "__main__":
    key = os.urandom(16)
    iv = os.urandom(12)
    mac_key = os.urandom(32)  # Updated to 32 bytes for Poly1305
    associated_data = b"benchmark|round=1"
    folder_path = "./generate_files"
    repetitions = 10

    print(f"{'File':<15}{'Size (KB)':<10}{'Avg Time (ms)':<15}{'Peak Mem (KB)':<15}{'Auth Time (ms)':<15}")
    print("-" * 70)

    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"Directory {folder_path} does not exist")

    for filename in sorted(os.listdir(folder_path)):
        file_path = os.path.join(folder_path, filename)
        if not os.path.isfile(file_path):
            continue

        file_size_kb = os.path.getsize(file_path) / 1024
        total_time = 0
        total_auth_time = 0
        peak_memory = 0

        for _ in range(repetitions):
            with open(file_path, "rb") as f:
                data = f.read()

            cipher = GrainSoft128AEAD(key, iv)
            tracemalloc.start()
            start = time.perf_counter()
            ciphertext, tag = cipher.encrypt_and_tag(data, mac_key, associated_data)
            end = time.perf_counter()
            start_auth = time.perf_counter()
            cipher._get_poly1305(ciphertext, mac_key, associated_data)
            end_auth = time.perf_counter()
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            total_time += (end - start) * 1000
            total_auth_time += (end_auth - start_auth) * 1000
            peak_memory = max(peak_memory, peak / 1024)

        avg_time = total_time / repetitions
        avg_auth_time = total_auth_time / repetitions
        print(f"{filename:<15}{file_size_kb:<10.1f}{avg_time:<15.2f}{peak_memory:<15.2f}{avg_auth_time:<15.2f}")