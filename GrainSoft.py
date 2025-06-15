import time
import hashlib
import hmac
import os
import gc
import psutil
import statistics
from typing import Tuple, List
import glob


class GrainSoft32:
    """
    GrainSoft32 - A lightweight stream cipher based on Grain
    but optimized for 32-bit software implementations
    """
    
    def __init__(self, key: bytes, iv: bytes):
        """
        Initialize the cipher with a key and IV
        
        Args:
            key: 10-byte key (80 bits)
            iv: 8-byte initialization vector (64 bits)
        """
        if len(key) != 10:
            raise ValueError("Key must be 10 bytes (80 bits)")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes (64 bits)")
            
        # Convert key and IV to bits
        self.key_bits = self._bytes_to_bits(key)
        self.iv_bits = self._bytes_to_bits(iv)
        
        # Initialize LFSR (80 bits) and NFSR (80 bits)
        self.lfsr = [0] * 80
        self.nfsr = [0] * 80
        
        # Load LFSR with IV and padded with 1's
        for i in range(64):
            self.lfsr[i] = self.iv_bits[i]
        for i in range(64, 80):
            self.lfsr[i] = 1
            
        # Load NFSR with key
        for i in range(80):
            self.nfsr[i] = self.key_bits[i]
            
        # Initialize cipher by running 160 clock cycles without output
        self._initialize()
        
    def _initialize(self):
        """Initialize the cipher by running 160 clock cycles"""
        for _ in range(160):
            lfsr_feedback = self._lfsr_feedback()
            nfsr_feedback = self._nfsr_feedback()
            
            # During initialization, output bit is XORed with both registers
            output = self._output_function()
            
            # Update LFSR and NFSR with feedback XORed with output bit
            self.lfsr = [lfsr_feedback ^ output] + self.lfsr[:-1]
            self.nfsr = [nfsr_feedback ^ output] + self.nfsr[:-1]
            
    def _lfsr_feedback(self) -> int:
        """Calculate LFSR feedback bit using primitive polynomial"""
        return self.lfsr[0] ^ self.lfsr[13] ^ self.lfsr[23] ^ self.lfsr[38] ^ self.lfsr[51] ^ self.lfsr[62]
        
    def _nfsr_feedback(self) -> int:
        """Calculate NFSR feedback bit using nonlinear function"""
        # Simplified nonlinear function for GrainSoft32
        return (self.nfsr[0] ^ 
                self.lfsr[0] ^ 
                self.nfsr[9] ^ 
                self.nfsr[14] ^ 
                self.nfsr[21] ^ 
                self.nfsr[28] ^ 
                self.nfsr[33] ^ 
                self.nfsr[37] ^ 
                self.nfsr[45] ^ 
                self.nfsr[52] ^ 
                self.nfsr[60] ^ 
                self.nfsr[63] ^
                (self.nfsr[9] & self.nfsr[15]) ^
                (self.nfsr[17] & self.nfsr[30]) ^
                (self.nfsr[37] & self.nfsr[45]) ^
                (self.nfsr[9] & self.nfsr[52] & self.nfsr[72]))
                
    def _output_function(self) -> int:
        """Calculate output bit from LFSR and NFSR state"""
        h = (self.lfsr[3] ^ 
             self.lfsr[25] ^ 
             self.lfsr[46] ^ 
             self.lfsr[64] ^ 
             self.nfsr[11] ^ 
             self.nfsr[39] ^
             (self.lfsr[25] & self.lfsr[46]) ^
             (self.lfsr[3] & self.lfsr[64]) ^
             (self.lfsr[46] & self.nfsr[11]) ^
             (self.lfsr[25] & self.nfsr[39]) ^
             (self.lfsr[3] & self.lfsr[46] & self.lfsr[64]))
             
        return h ^ self.nfsr[0]
        
    def clock(self) -> int:
        """
        Clock the cipher once and return the output bit
        """
        output = self._output_function()
        
        lfsr_feedback = self._lfsr_feedback()
        nfsr_feedback = self._nfsr_feedback()
        
        # Shift registers
        self.lfsr = [lfsr_feedback] + self.lfsr[:-1]
        self.nfsr = [nfsr_feedback] + self.nfsr[:-1]
        
        return output
        
    def generate_keystream(self, length: int) -> List[int]:
        """
        Generate keystream bits
        
        Args:
            length: Number of keystream bits to generate
            
        Returns:
            List of keystream bits
        """
        return [self.clock() for _ in range(length)]
        
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext
        
        Args:
            plaintext: Bytes to encrypt
            
        Returns:
            Encrypted bytes
        """
        plaintext_bits = self._bytes_to_bits(plaintext)
        keystream_bits = self.generate_keystream(len(plaintext_bits))
        
        # XOR plaintext with keystream
        ciphertext_bits = [p ^ k for p, k in zip(plaintext_bits, keystream_bits)]
        
        return self._bits_to_bytes(ciphertext_bits)
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext
        
        Args:
            ciphertext: Bytes to decrypt
            
        Returns:
            Decrypted bytes
        """
        # Decryption is the same as encryption in stream ciphers
        return self.encrypt(ciphertext)
        
    @staticmethod
    def _bytes_to_bits(data: bytes) -> List[int]:
        """Convert bytes to list of bits"""
        result = []
        for byte in data:
            # Convert each byte to 8 bits (MSB first)
            for i in range(7, -1, -1):
                result.append((byte >> i) & 1)
        return result
        
    @staticmethod
    def _bits_to_bytes(bits: List[int]) -> bytes:
        """Convert list of bits to bytes"""
        # Ensure bit list length is a multiple of 8
        padded_bits = bits.copy()
        while len(padded_bits) % 8 != 0:
            padded_bits.append(0)
            
        result = bytearray()
        for i in range(0, len(padded_bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | padded_bits[i + j]
            result.append(byte)
            
        return bytes(result)


class AuthenticatedGrainSoft32:
    """
    Authenticated encryption with GrainSoft32 cipher and HMAC-SHA256
    """
    
    def __init__(self, key: bytes, iv: bytes, auth_key: bytes = None):
        """
        Initialize authenticated encryption with GrainSoft32
        
        Args:
            key: Encryption key (10 bytes)
            iv: Initialization vector (8 bytes)
            auth_key: Authentication key for HMAC (32 bytes, optional)
                     If not provided, a key will be derived from the encryption key
        """
        self.cipher = GrainSoft32(key, iv)
        
        # If auth_key is not provided, derive one from the encryption key
        if auth_key is None:
            self.auth_key = hashlib.sha256(key + iv).digest()
        else:
            if len(auth_key) != 32:
                raise ValueError("Authentication key must be 32 bytes")
            self.auth_key = auth_key
            
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt and authenticate plaintext
        
        Args:
            plaintext: Bytes to encrypt
            
        Returns:
            Ciphertext with HMAC appended
        """
        ciphertext = self.cipher.encrypt(plaintext)
        mac = hmac.new(self.auth_key, ciphertext, hashlib.sha256).digest()
        
        return ciphertext + mac
        
    def decrypt(self, ciphertext_with_mac: bytes) -> Tuple[bytes, bool]:
        """
        Decrypt and verify ciphertext
        
        Args:
            ciphertext_with_mac: Ciphertext with HMAC appended
            
        Returns:
            Tuple of (decrypted plaintext, verification success)
        """
        if len(ciphertext_with_mac) < 32:
            return b'', False
            
        # Split ciphertext and MAC
        ciphertext = ciphertext_with_mac[:-32]
        received_mac = ciphertext_with_mac[-32:]
        
        # Calculate and verify MAC
        expected_mac = hmac.new(self.auth_key, ciphertext, hashlib.sha256).digest()
        is_valid = hmac.compare_digest(expected_mac, received_mac)
        
        if is_valid:
            plaintext = self.cipher.decrypt(ciphertext)
            return plaintext, True
        else:
            return b'', False


class FileCipherBenchmark:
    """
    Benchmark authentication encryption performance using files
    """
    
    def __init__(self, iterations=5, files_directory="./../generate_files"):
        """
        Initialize benchmarking
        
        Args:
            iterations: Number of iterations to run for each file
            files_directory: Directory containing test files
        """
        self.iterations = iterations
        self.files_directory = files_directory
        
        # Ensure the directory exists
        if not os.path.exists(files_directory):
            raise ValueError(f"Directory '{files_directory}' does not exist")
            
        # Get list of files in the directory
        self.test_files = self._get_test_files()
        
        if not self.test_files:
            raise ValueError(f"No files found in '{files_directory}'")
            
        print(f"Found {len(self.test_files)} test files:")
        for file_path, size in self.test_files:
            print(f"  {os.path.basename(file_path)}: {size} bytes")
    
    def _get_test_files(self):
        """
        Get list of files in the test directory with their sizes
        
        Returns:
            List of tuples (file_path, file_size)
        """
        files = []
        
        # Get all files in the directory
        for file_path in glob.glob(os.path.join(self.files_directory, "*")):
            if os.path.isfile(file_path):
                file_size = os.path.getsize(file_path)
                files.append((file_path, file_size))
                
        # Sort by file size
        return sorted(files, key=lambda x: x[1])
            
    def generate_key_iv(self) -> Tuple[bytes, bytes]:
        """
        Generate random key and IV
        
        Returns:
            Tuple of (key, iv)
        """
        key = os.urandom(10)  # 80 bits
        iv = os.urandom(8)    # 64 bits
        return key, iv
        
    def get_memory_usage(self) -> int:
        """
        Get current memory usage of the process
        
        Returns:
            Memory usage in bytes
        """
        process = psutil.Process(os.getpid())
        return process.memory_info().rss
        
    def benchmark(self) -> dict:
        """
        Run benchmarks
        
        Returns:
            Dictionary with benchmark results
        """
        results = {}
        
        for file_path, file_size in self.test_files:
            file_name = os.path.basename(file_path)
            
            file_results = {
                'file_size': file_size,
                'encryption_times': [],
                'decryption_times': [],
                'encryption_speed': [],  # bytes per second
                'decryption_speed': [],  # bytes per second
                'memory_usage': [],
                'verification_success': [],
            }
            
            print(f"\nBenchmarking file: {file_name} ({file_size} bytes)")
            
            # Read the file content once
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
            for i in range(self.iterations):
                print(f"  Iteration {i+1}/{self.iterations}:")
                
                # Force garbage collection before measuring memory
                gc.collect()
                
                # Generate fresh key and IV for each iteration
                key, iv = self.generate_key_iv()
                
                # Measure memory before
                mem_before = self.get_memory_usage()
                
                # Create a new cipher instance for each iteration
                cipher = AuthenticatedGrainSoft32(key, iv)
                
                # Measure encryption time
                enc_start = time.time()
                encrypted = cipher.encrypt(file_content)
                enc_end = time.time()
                enc_time = enc_end - enc_start
                
                # Calculate encryption speed
                enc_speed = file_size / enc_time if enc_time > 0 else 0
                
                # Create a new cipher instance for decryption
                cipher_dec = AuthenticatedGrainSoft32(key, iv)
                
                # Measure decryption time
                dec_start = time.time()
                decrypted, is_valid = cipher_dec.decrypt(encrypted)
                dec_end = time.time()
                dec_time = dec_end - dec_start
                
                # Calculate decryption speed
                dec_speed = file_size / dec_time if dec_time > 0 else 0
                
                # Check if decryption was successful
                decryption_success = (decrypted == file_content)
                
                # Measure memory after
                mem_after = self.get_memory_usage()
                mem_delta = mem_after - mem_before
                
                # Store results
                file_results['encryption_times'].append(enc_time)
                file_results['decryption_times'].append(dec_time)
                file_results['encryption_speed'].append(enc_speed)
                file_results['decryption_speed'].append(dec_speed)
                file_results['memory_usage'].append(mem_delta)
                file_results['verification_success'].append(is_valid and decryption_success)
                
                # Print iteration results
                print(f"    Encryption time: {enc_time:.6f} seconds ({enc_speed:.2f} bytes/sec)")
                print(f"    Decryption time: {dec_time:.6f} seconds ({dec_speed:.2f} bytes/sec)")
                print(f"    Memory delta: {mem_delta} bytes")
                print(f"    HMAC valid: {is_valid}")
                print(f"    Decryption correct: {decryption_success}")
                
                # Clean up to reduce memory pressure
                del encrypted
                del decrypted
                gc.collect()
            
            # Calculate averages and store in results
            results[file_name] = {
                'file_size': file_size,
                'avg_encryption_time': statistics.mean(file_results['encryption_times']),
                'avg_decryption_time': statistics.mean(file_results['decryption_times']),
                'avg_encryption_speed': statistics.mean(file_results['encryption_speed']),
                'avg_decryption_speed': statistics.mean(file_results['decryption_speed']),
                'avg_memory_delta': statistics.mean(file_results['memory_usage']),
                'verification_success_rate': sum(file_results['verification_success']) / len(file_results['verification_success']) * 100,
                'detail': file_results
            }
            
        return results

    def save_results_to_csv(self, results, output_file="benchmark_results.csv"):
        """
        Save benchmark results to a CSV file
        
        Args:
            results: Benchmark results dictionary
            output_file: Output CSV file path
        """
        import csv
        
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = [
                'File Name', 
                'File Size (bytes)', 
                'Avg Encryption Time (s)', 
                'Avg Decryption Time (s)',
                'Avg Encryption Speed (bytes/s)', 
                'Avg Decryption Speed (bytes/s)',
                'Avg Memory Usage (bytes)', 
                'Verification Success Rate (%)'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for file_name, result in results.items():
                writer.writerow({
                    'File Name': file_name,
                    'File Size (bytes)': result['file_size'],
                    'Avg Encryption Time (s)': f"{result['avg_encryption_time']:.6f}",
                    'Avg Decryption Time (s)': f"{result['avg_decryption_time']:.6f}",
                    'Avg Encryption Speed (bytes/s)': f"{result['avg_encryption_speed']:.2f}",
                    'Avg Decryption Speed (bytes/s)': f"{result['avg_decryption_speed']:.2f}",
                    'Avg Memory Usage (bytes)': f"{result['avg_memory_delta']:.2f}",
                    'Verification Success Rate (%)': f"{result['verification_success_rate']:.2f}"
                })
                
        print(f"\nResults saved to {output_file}")


def main():
    # Create and run file benchmarks
    print("GrainSoft32 Cipher File Benchmarking")
    print("====================================")
    
    # Define directory containing test files
    files_directory = "./../generate_files"  # Update this to your directory path
    
    try:
        benchmark = FileCipherBenchmark(iterations=5, files_directory=files_directory)
        results = benchmark.benchmark()
        
        # Print summary
        print("\nBenchmark Summary")
        print("=================")
        
        for file_name, result in results.items():
            print(f"\nFile: {file_name} ({result['file_size']} bytes)")
            print(f"  Average Encryption Time: {result['avg_encryption_time']:.6f} seconds")
            print(f"  Average Decryption Time: {result['avg_decryption_time']:.6f} seconds")
            print(f"  Average Encryption Speed: {result['avg_encryption_speed']:.2f} bytes/sec")
            print(f"  Average Decryption Speed: {result['avg_decryption_speed']:.2f} bytes/sec")
            print(f"  Average Memory Usage Delta: {result['avg_memory_delta']:.2f} bytes")
            print(f"  Verification Success Rate: {result['verification_success_rate']:.2f}%")
        
        # Save results to CSV
        benchmark.save_results_to_csv(results)
            
    except ValueError as e:
        print(f"Error: {e}")
        print("\nMake sure the directory exists and contains the test files.")
        print(f"Current directory: {os.getcwd()}")
        print("You can change the directory in the code by modifying the 'files_directory' variable.")


if __name__ == "__main__":
    main()