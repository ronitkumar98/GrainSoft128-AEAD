# Linear Complexity Analysis for GrainSoft128AEAD Keystream
from sage.all import *

# Load keystream from file
try:
    with open("keystream_bits.txt", "r") as f:
        bits = [int(c) for c in f.read().strip() if c in '01']
except FileNotFoundError:
    print("Error: keystream_bits.txt not found. Ensure it exists in the current directory.")
    exit()

# Ensure we have enough bits
if len(bits) < 1000:
    print(f"Error: Keystream too short ({len(bits)} bits). Need at least 1000 bits.")
    exit()

# Define finite field and polynomial ring
F = GF(2)
R = PolynomialRing(F, 'x')

# Compute linear complexity
conn_poly = R.lfsr_connection_polynomial(bits)
linear_complexity = conn_poly.degree()

# Output results
print(f"Keystream Length: {len(bits)} bits")
print(f"Linear Complexity: {linear_complexity}")
print(f"Expected Complexity (Random): ~{len(bits)//2}")
if linear_complexity < len(bits) // 4:
    print("Warning: Linear complexity is low, indicating potential predictability.")
elif linear_complexity >= len(bits) // 2:
    print("Good: Linear complexity is high, suggesting strong randomness.")
else:
    print("Moderate: Linear complexity is acceptable but could be improved.")