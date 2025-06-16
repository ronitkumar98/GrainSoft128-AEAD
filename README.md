# Cipher Execution Guide

This repository provides instructions for running and analyzing the following ciphers: **GrainSoft-HMAC**, **Grain128 AEAD**, **Salsa20**, and **ChaCha20**. Follow the steps below based on the cipher you want to use.

## Prerequisites

- **Python 3.x**: Required for running GrainSoft-HMAC, Grain128 AEAD, Salsa20, and ChaCha20 scripts
- **SageMath**: Required for cryptanalysis in the `sage-test` folder
- **Ubuntu or WSL**: Required for running SageMath scripts in the `sage-test` folder

## Case 1: Running GrainSoft-HMAC or Grain128 AEAD

### Step 1: Navigate to the Desired Directory
Move to the directory containing the cipher files for either GrainSoft-HMAC or Grain128 AEAD.

### Step 2: Running GrainSoft-HMAC
1. Open two terminals in the GrainSoft directory
2. In the first terminal, start the server:
   ```bash
   python server.py
   ```
3. In the second terminal, start the client:
   ```bash
   python client.py
   ```

### Step 3: Running Grain128 AEAD
1. Open two terminals in the Grain128 AEAD directory
2. In the first terminal, start the server:
   ```bash
   python server_automate.py
   ```
3. In the second terminal, start the client:
   ```bash
   python client_automate.py
   ```

## Case 2: Running Salsa20 or ChaCha20

For Salsa20 or ChaCha20, execute the respective Python files to measure execution time:

**For Salsa20:**
```bash
python salsa20.py
```

**For ChaCha20:**
```bash
python chacha20.py
```

## Case 3: Cryptanalysis of GrainSoft-HMAC

### Step 1: Generate Keystream
Run the cryptanalysis script to generate the keystream:
```bash
python Grainsoft_cryptanalysis.py
```
This will create a `keystreambits.txt` file containing the keystream in bits format (only 0s and 1s, no other string literals).

### Step 2: Move Keystream File
Copy or move the `keystreambits.txt` file to the `sage-test` folder.

### Step 3: Set Up SageMath Environment
1. Open the `sage-test` folder in an Ubuntu or WSL environment
2. Ensure SageMath is installed. If not, install it using:
   ```bash
   sudo apt-get install sagemath
   ```

### Step 4: Run Cryptanalysis Tests
Execute individual test scripts in the `sage-test` folder using SageMath:
```bash
sage filename.py
```
Replace `filename.py` with the specific test script name.

## Notes

- Ensure all Python scripts are executable and dependencies are installed
- For GrainSoft-HMAC and Grain128 AEAD, both server and client must be running simultaneously in separate terminals
- The `keystreambits.txt` file must contain only bit values (0s and 1s) for compatibility with SageMath scripts
