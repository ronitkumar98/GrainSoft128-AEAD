import struct

class Grain128AEAD:
    def __init__(self, key, iv):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits)")
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes (96 bits)")
        self.key = key
        self.iv = iv
        self.mask = (1 << 128) - 1
        self.lfsr = 0
        self.nfsr = 0
        self.accum = 0
        self.sr = 0
        self.initialize()

    def reset(self):
        self.lfsr = 0
        self.nfsr = 0
        self.accum = 0
        self.sr = 0
        self.initialize()

    def initialize(self):
        for i in range(96):
            bit = (self.iv[i // 8] >> (i % 8)) & 1
            self.lfsr |= (bit << i)
        self.lfsr |= ((1 << 31) - 1) << 96
        for i in range(128):
            bit = (self.key[i // 8] >> (i % 8)) & 1
            self.nfsr |= (bit << i)
        for i in range(320):
            ks_bit = self._clock(True)
            self.lfsr = ((self.lfsr << 1) | ks_bit) & self.mask
            self.nfsr = ((self.nfsr << 1) | ks_bit) & self.mask
            if i >= 192:
                pre_output = self._get_pre_output()
                self.sr = ((self.sr << 1) | pre_output) & self.mask

    def _get_pre_output(self):
        h = self._compute_h()
        lfsr_bits = [(self.lfsr >> i) & 1 for i in [8, 43, 55, 67, 68]]
        nfsr_bits = [(self.nfsr >> i) & 1 for i in [5, 33, 67, 85]]
        return (h ^ sum(lfsr_bits) % 2 ^ sum(nfsr_bits) % 2) & 1

    def _compute_h(self):
        lfsr_indices = [2, 11, 20, 29, 38, 47, 56, 65]
        nfsr_indices = [63, 95]
        x = [(self.lfsr >> i) & 1 for i in lfsr_indices] + [(self.nfsr >> i) & 1 for i in nfsr_indices]
        return ((x[0] & x[1]) ^ (x[2] & x[3]) ^ (x[4] & x[5]) ^ (x[6] & x[7]) ^ (x[8] & x[9]) ^
                (x[0] & x[4] & x[8]) ^ (x[1] & x[5] & x[9]) ^ (x[2] & x[6] & x[8]) ^
                (x[3] & x[7] & x[9]) ^ (x[4] & x[5] & x[6] & x[7])) & 1

    def _clock(self, init=False):
        lfsr_bits = [(self.lfsr >> i) & 1 for i in [0, 31, 46, 57, 89, 120, 127]]
        lfsr_fb = sum(lfsr_bits) % 2
        nfsr_indices = [0, 17, 19, 27, 34, 42, 46, 64, 70, 79, 87, 95, 99, 103, 106, 117, 121]
        nonlinear_pairs = [
            (0, 9), (14, 15), (21, 23), (24, 25), (36, 37), (40, 41), (48, 49), (50, 51),
            (52, 53), (55, 56), (57, 59), (60, 61), (66, 68), (69, 70), (72, 73), (74, 75),
            (76, 77), (78, 79), (82, 83), (84, 85), (86, 87), (91, 92), (93, 94), (95, 97),
            (98, 99), (101, 102), (103, 105), (106, 108), (109, 110), (111, 112), (113, 114),
            (115, 116), (117, 119)
        ]
        nfsr_bits = [(self.nfsr >> i) & 1 for i in nfsr_indices]
        nonlinear_terms = [(self.nfsr >> i) & (self.nfsr >> j) & 1 for i, j in nonlinear_pairs]
        nfsr_fb = (sum(nfsr_bits) % 2 ^ sum(nonlinear_terms) % 2 ^ lfsr_bits[0])
        self.lfsr = ((self.lfsr >> 1) | (lfsr_fb << 127)) & self.mask
        self.nfsr = ((self.nfsr >> 1) | (nfsr_fb << 127)) & self.mask
        h = self._compute_h()
        ks_bit = (h ^ (self.nfsr & 1)) & 1
        if not init and not hasattr(self, '_skip_auth'):
            pre_output = self._get_pre_output()
            self.sr = ((self.sr << 1) | pre_output) & self.mask
        return ks_bit

    def _generate_keystream(self, length, auth_bits=None):
        ks_bytes = bytearray()
        bit_idx = 0
        for i in range(length):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | self._clock()
                if auth_bits is not None:
                    bit = (auth_bits[i] >> (j)) & 1
                    if bit:
                        self.accum ^= self.sr
                    bit_idx += 1
            ks_bytes.append(byte)
        return bytes(ks_bytes)

    def encrypt(self, plaintext, associated_data=b''):
        self.reset()
        for byte in associated_data:
            for i in range(8):
                bit = (byte >> i) & 1
                if bit:
                    self.accum ^= self.sr
                self._clock()
        ciphertext = self._generate_keystream(len(plaintext), plaintext)
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, ciphertext))
        tag = self._finalize()
        return ciphertext, tag

    def decrypt(self, ciphertext, associated_data=b''):
        self.reset()
        for byte in associated_data:
            for i in range(8):
                bit = (byte >> i) & 1
                if bit:
                    self.accum ^= self.sr
                self._clock()
        plaintext = self._generate_keystream(len(ciphertext), ciphertext)
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, plaintext))
        tag = self._finalize()
        return plaintext, tag

    def _finalize(self):
        self._skip_auth = True
        tag_bits = 0
        for i in range(64):
            bit = self._clock()
            if bit:
                self.accum ^= self.sr
            tag_bits |= (bit << i)
        delattr(self, '_skip_auth')
        return struct.pack('<Q', tag_bits & ((1 << 64) - 1))

    def get_tag(self, ciphertext, associated_data=b''):
        self.reset()
        for byte in associated_data:
            for i in range(8):
                bit = (byte >> i) & 1
                if bit:
                    self.accum ^= self.sr
                self._clock()
        for byte in ciphertext:
            for i in range(8):
                bit = (byte >> i) & 1
                if bit:
                    self.accum ^= self.sr
                self._clock()
        return self._finalize()

if __name__ == "__main__":
    key = b'16_byte_key_1234'
    iv = b'12_byte_iv_123'
    cipher = Grain128AEAD(key, iv)
    plaintext = b"Hello, Grain128AEAD!"
    ad = b"Some associated data"
    ciphertext, tag = cipher.encrypt(plaintext, ad)
    decrypted, dec_tag = cipher.decrypt(ciphertext, ad)
    auth_tag = cipher.get_tag(ciphertext, ad)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")
    print(f"Decrypted: {decrypted}")
    print(f"Dec Tag: {dec_tag.hex()}")
    print(f"Auth Tag: {auth_tag.hex()}")
    print(f"Decryption OK: {plaintext == decrypted}")
    print(f"Tag OK: {tag == dec_tag == auth_tag}")