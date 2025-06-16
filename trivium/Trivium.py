import array
from typing import Union, List

class Trivium:
    
    def __init__(self, key: Union[List[int], bytes], iv: Union[List[int], bytes]):
        # Convert list inputs to array
        if isinstance(key, list):
            key = array.array('B', key[:80])
        if isinstance(iv, list):
            iv = array.array('B', iv[:80])
            
        # Initialize state using efficient array
        self.state = array.array('B', [0] * 288)
        
        # Pre-calculate indices for frequent access
        self.idx = {
            't1': (65, 92, 90, 91, 170),
            't2': (161, 176, 174, 175, 263),
            't3': (242, 287, 285, 286, 68)
        }
        
        # Fast state initialization
        for i in range(80):
            self.state[i] = key[i] if i < len(key) else 0
            self.state[i + 93] = iv[i] if i < len(iv) else 0
        
        # Set last three bits
        self.state[285] = self.state[286] = self.state[287] = 1
        
        # Warm up cipher with unrolled loop
        for _ in range(0, 4 * 288, 4):
            for _ in range(4):
                self._gen_keystream_bit()
    
    def _gen_keystream_bit(self) -> int:
        """Optimized keystream bit generation"""
        # Use local variables for faster access
        state = self.state
        idx = self.idx
        
        # Calculate t values using pre-calculated indices
        t1_idx = idx['t1']
        t2_idx = idx['t2']
        t3_idx = idx['t3']
        
        t1 = state[t1_idx[0]] ^ state[t1_idx[1]]
        t2 = state[t2_idx[0]] ^ state[t2_idx[1]]
        t3 = state[t3_idx[0]] ^ state[t3_idx[1]]
        
        z = t1 ^ t2 ^ t3
        
        t1 ^= (state[t1_idx[2]] & state[t1_idx[3]]) ^ state[t1_idx[4]]
        t2 ^= (state[t2_idx[2]] & state[t2_idx[3]]) ^ state[t2_idx[4]]
        t3 ^= (state[t3_idx[2]] & state[t3_idx[3]]) ^ state[t3_idx[4]]
        
        # Efficient state rotation using memoryview
        last = state[-1]
        state_view = memoryview(state)
        state_view[1:] = state_view[:-1]
        state[0] = last
        
        # Update state
        state[93] = t1
        state[177] = t2
        
        return z
    
    def encrypt(self, data: Union[bytes, bytearray]) -> bytes:
        """Optimized encryption with chunk processing"""
        # Pre-allocate result array
        result = array.array('B', [0] * len(data))
        data_view = memoryview(data)
        
        # Process data in chunks for better performance
        chunk_size = 1024
        for i in range(0, len(data), chunk_size):
            chunk_end = min(i + chunk_size, len(data))
            chunk = data_view[i:chunk_end]
            
            # Process each byte in chunk
            for j, byte in enumerate(chunk):
                key_byte = 0
                # Generate 8 bits of keystream
                for _ in range(8):
                    key_byte = (key_byte << 1) | self._gen_keystream_bit()
                result[i + j] = byte ^ key_byte
        
        return bytes(result)

# Optional: Performance test function
def run_performance_test():
    import time
    import os
    
    print("Running performance test...")
    
    # Test parameters
    key = [1] * 80
    iv = [0] * 80
    test_sizes = [1024, 10240, 102400]  # Test with different file sizes
    
    cipher = Trivium(key, iv)
    
    for size in test_sizes:
        test_data = os.urandom(size)  # Generate random test data
        
        # Measure encryption time
        start_time = time.time()
        encrypted = cipher.encrypt(test_data)
        encryption_time = time.time() - start_time
        
        print(f"\nTest with {size/1024:.2f}KB data:")
        print(f"Encryption time: {encryption_time:.6f} seconds")
        print(f"Speed: {size/(1024*1024*encryption_time):.2f} MB/s")

if __name__ == "__main__":
    run_performance_test()