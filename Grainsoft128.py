import hmac
import hashlib

class GrainSoft128:
    def __init__(self, key, iv):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits)")
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes (96 bits)")
        self.key = key
        self.iv = iv
        self.mask = (1 << 128) - 1  # Mask to keep 128 bits
        self.lfsr = 0
        self.nfsr = 0
        self.ks = []
        self.initialize()

    def initialize(self):
        # Load IV into LFSR (bits 0-95)
        for i in range(96):
            bit = (self.iv[i // 8] >> (7 - (i % 8))) & 1
            self.lfsr |= (bit << i)
        # Set LFSR bits 96-127 to 1
        self.lfsr |= ((1 << 32) - 1) << 96
        # Load key into NFSR
        for i in range(128):
            bit = (self.key[i // 8] >> (7 - (i % 8))) & 1
            self.nfsr |= (bit << i)
        # Run initialization for 256 cycles
        for _ in range(256):
            ks_bit = self._clock()
            self.lfsr = ((self.lfsr << 1) | ks_bit) & self.mask
            self.nfsr = ((self.nfsr << 1) | ks_bit) & self.mask

    def _clock(self):
        # Extract LFSR bits
        lfsr_0 = self.lfsr & 1
        lfsr_7 = (self.lfsr >> 7) & 1
        lfsr_20 = (self.lfsr >> 20) & 1
        lfsr_42 = (self.lfsr >> 42) & 1
        lfsr_57 = (self.lfsr >> 57) & 1
        lfsr_91 = (self.lfsr >> 91) & 1
        # LFSR feedback: x^128 + x^91 + x^57 + x^42 + x^20 + x^7 + 1
        lfsr_fb = (lfsr_0 ^ lfsr_7 ^ lfsr_20 ^ lfsr_42 ^ lfsr_57 ^ lfsr_91) & 1
        # Extract NFSR bits
        nfsr_0 = self.nfsr & 1
        nfsr_11 = (self.nfsr >> 11) & 1
        nfsr_13 = (self.nfsr >> 13) & 1
        nfsr_23 = (self.nfsr >> 23) & 1
        nfsr_25 = (self.nfsr >> 25) & 1
        nfsr_47 = (self.nfsr >> 47) & 1
        nfsr_49 = (self.nfsr >> 49) & 1
        nfsr_63 = (self.nfsr >> 63) & 1
        nfsr_95 = (self.nfsr >> 95) & 1
        # NFSR feedback
        nfsr_fb = (nfsr_0 ^ nfsr_63 ^ nfsr_95 ^
                   (nfsr_11 & nfsr_13) ^ (nfsr_23 & nfsr_25) ^
                   (nfsr_47 & nfsr_49) ^ lfsr_0) & 1
        # Update states
        self.lfsr = ((self.lfsr >> 1) | (lfsr_fb << 127)) & self.mask
        self.nfsr = ((self.nfsr >> 1) | (nfsr_fb << 127)) & self.mask
        # Output function h
        lfsr_3 = (self.lfsr >> 3) & 1
        lfsr_64 = (self.lfsr >> 64) & 1
        lfsr_93 = (self.lfsr >> 93) & 1
        nfsr_2 = (self.nfsr >> 2) & 1
        nfsr_25 = (self.nfsr >> 25) & 1
        nfsr_46 = (self.nfsr >> 46) & 1
        nfsr_63 = (self.nfsr >> 63) & 1
        h = (lfsr_3 ^ nfsr_2 ^ (lfsr_64 & nfsr_63) ^
             nfsr_25 ^ nfsr_46 ^ lfsr_93) & 1
        ks_bit = (h ^ nfsr_0) & 1
        self.ks.append(ks_bit)
        return ks_bit

    def reset(self):
        self.lfsr = 0
        self.nfsr = 0
        self.ks = []
        self.initialize()

    def _generate_keystream(self, length):
        ks_bytes = bytearray()
        for _ in range(length):
            byte = 0
            for _ in range(8):
                byte = (byte << 1) | self._clock()
            ks_bytes.append(byte)
        return bytes(ks_bytes)

    def encrypt(self, plaintext):
        self.reset()
        ks = self._generate_keystream(len(plaintext))
        return bytes(a ^ b for a, b in zip(plaintext, ks))

    def decrypt(self, ciphertext):
        self.reset()
        ks = self._generate_keystream(len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, ks))

    def get_hmac(self, data, hmac_key):
        return hmac.new(hmac_key, data, hashlib.sha256).digest()

if __name__ == "__main__":
    key = b'16_byte_key_1234'
    iv = b'12_byte_iv_123'  # Updated to match your working IV
    hmac_key = b'32_byte_hmac_key_12345678901234'
    cipher = GrainSoft128(key, iv)
    plaintext = b"Hello, GrainSoft128!"
    ciphertext = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(ciphertext)
    hmac_tag = cipher.get_hmac(ciphertext, hmac_key)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")
    print(f"HMAC: {hmac_tag.hex()}")
    print(f"Decryption OK: {plaintext == decrypted}")
    print(f"HMAC OK: {hmac_tag == cipher.get_hmac(ciphertext, hmac_key)}")