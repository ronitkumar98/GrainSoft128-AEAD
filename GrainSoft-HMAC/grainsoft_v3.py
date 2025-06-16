import hashlib

class GrainSoft128AEAD:
    def __init__(self, key: bytes, iv: bytes):
        assert len(key) == 16
        assert len(iv) == 12
        self.key = key
        self.iv = iv
        self._initialize()

    def _initialize(self):
        # Convert key and IV to bits
        key_bits = self._bytes_to_bits(self.key)
        iv_bits = self._bytes_to_bits(self.iv + b'\xFF\xFF\xFF\xFF')  # Pad to 128 bits

        # Initialize LFSR and NFSR
        self.lfsr = iv_bits.copy()
        self.nfsr = key_bits.copy()

        # Proper warm-up: 320 rounds
        for _ in range(320):
            z = self._get_keystream_bit()
            nfsr_fb = self._nfsr_feedback(z)
            lfsr_fb = self._lfsr_feedback()
            self.nfsr = self.nfsr[1:] + [nfsr_fb ^ self.lfsr[0]]
            self.lfsr = self.lfsr[1:] + [lfsr_fb]

    def _bytes_to_bits(self, b):
        return [(byte >> i) & 1 for byte in b for i in reversed(range(8))]

    def _bits_to_bytes(self, bits):
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j] if i + j < len(bits) else 0
            out.append(byte)
        return bytes(out)

    def _lfsr_feedback(self):
        taps = [0, 7, 38, 70, 81, 96]
        fb = self.lfsr[taps[0]]
        for tap in taps[1:]:
            fb ^= self.lfsr[tap]
        return fb

    def _nfsr_feedback(self, z):
        taps = [0, 26, 56, 91, 96]
        nonlinear = self.nfsr[3] & self.nfsr[67] ^ self.nfsr[11] & self.lfsr[13]
        fb = self.nfsr[taps[0]]
        for tap in taps[1:]:
            fb ^= self.nfsr[tap]
        return fb ^ z ^ nonlinear

    def _get_keystream_bit(self):
        taps = [2, 15, 36, 45, 64, 73, 89, 95]
        z = self.nfsr[taps[0]]
        for tap in taps[1:]:
            z ^= self.nfsr[tap]
        z ^= self.lfsr[93] ^ (self.lfsr[0] & self.nfsr[0])
        return z

    def _generate_keystream(self, num_bytes):
        keystream_bits = []
        for _ in range(num_bytes * 8):
            z = self._get_keystream_bit()
            nfsr_fb = self._nfsr_feedback(z)
            lfsr_fb = self._lfsr_feedback()
            self.nfsr = self.nfsr[1:] + [nfsr_fb ^ self.lfsr[0]]
            self.lfsr = self.lfsr[1:] + [lfsr_fb]
            keystream_bits.append(z)
        return self._bits_to_bytes(keystream_bits)

    def encrypt_and_tag(self, plaintext: bytes, mac_key: bytes):
        keystream = self._generate_keystream(len(plaintext))
        ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        tag = self._compute_mac(ciphertext, mac_key)
        return ciphertext, tag

    def decrypt_and_verify(self, ciphertext: bytes, tag: bytes, mac_key: bytes):
        # RESET internal state for decryption
        self._initialize()
        keystream = self._generate_keystream(len(ciphertext))
        plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])
        computed_tag = self._compute_mac(ciphertext, mac_key)
        if computed_tag != tag:
            raise ValueError("MAC check failed")
        return plaintext

    def _compute_mac(self, data: bytes, mac_key: bytes):
        h = hashlib.sha256(mac_key + data).digest()
        return h[:16]

# === Test ===
if __name__ == "__main__":
    from os import urandom

    key = urandom(16)
    iv = urandom(12)
    mac_key = urandom(16)
    plaintext = b" this is secure"

    cipher = GrainSoft128AEAD(key, iv)

    ciphertext, tag = cipher.encrypt_and_tag(plaintext, mac_key)
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    try:
        decrypted = cipher.decrypt_and_verify(ciphertext, tag, mac_key)
        print("Decrypted:", decrypted.decode())
    except ValueError:
        print("MAC verification failed.")
