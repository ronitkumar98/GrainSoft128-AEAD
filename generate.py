import random
import string

def generate_message(size_in_kb):
    """Generate a random alphanumeric string of given size in KB."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size_in_kb * 1024))

def generate_and_store_messages(sizes_in_kb):
    """Generate and store messages of different sizes."""
    for size in sizes_in_kb:
        message = generate_message(size)
        with open(f"message_{size}KB.txt", 'w') as file:
            file.write(message)
        print(f"Generated and stored {size}KB message in 'message_{size}KB.txt'")

# Specify message sizes in KB (e.g., 10 KB, 50 KB, 100 KB)
generate_and_store_messages([10, 50, 100,150,200])
