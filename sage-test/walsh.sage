# Walsh Transform Analysis for GrainSoft128AEAD Output Function
from sage.crypto.boolean_function import BooleanFunction
from sage.all import BooleanPolynomialRing
import time

print(" Starting Walsh Transform Analysis for GrainSoft128AEAD output function...")

# Start timing
start_time = time.time()

# Define the input variables
print(" Initializing Boolean polynomial ring...")
variables = ['l3', 'l64', 'l93', 'l10', 'n2', 'n25', 'n46', 'n63', 'n20']
P = BooleanPolynomialRing(len(variables), variables)
print(f" Boolean ring initialized in {time.time() - float(start_time):.2f} seconds")

# Map variable names to polynomial variables
v = {name: P.gen(i) for i, name in enumerate(variables)}

# Define the output function h(x) used in GrainSoft128AEAD
print(" Defining output Boolean function h...")
h = (
    v['l3'] + v['n2'] + v['l10'] + v['n25']
    + v['l64'] * v['n63']
    + v['n46'] * v['l93']
    + v['l10'] * v['n20']
    + v['l3'] * v['l93']
    + v['n2'] * v['n25'] * v['l64']
)
print(f" Function h defined in {time.time() - float(start_time):.2f} seconds")

# Create BooleanFunction instance
print(" Creating BooleanFunction object...")
bf = BooleanFunction(h)
print(f" BooleanFunction created in {time.time() - float(start_time):.2f} seconds")

# Compute Walsh Transform
print("Computing Walsh-Hadamard transform...")
walsh = bf.walsh_hadamard_transform()
n = len(variables)
max_walsh = max(abs(w) for w in walsh)
bias = max_walsh / (2 ** n)
print(f"Walsh transform complete in {time.time() - float(start_time):.2f} seconds")

# Results
print("\n🔍 Walsh Transform Results:")
print(f"  → Output Boolean Function h(x): {h}")
print(f"  → Number of Input Variables: {n}")
print(f"  → Maximum Walsh Coefficient: {max_walsh}")
print(f"  → Maximum Linear Bias: {float(bias):.6f}")

# Interpretation
if bias > 0.3:
    print("⚠️  Warning: High bias — potential vulnerability to linear cryptanalysis.")
elif bias < 0.15:
    print("Excellent: Very low bias — strong resistance to linear cryptanalysis.")
else:
    print("Moderate: Acceptable bias — might be improved for stronger security.")

# Total runtime
total_time = time.time() - start_time
print(f"\n Total Execution Time: {float(total_time):.2f} seconds")
