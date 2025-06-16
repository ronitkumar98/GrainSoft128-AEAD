Cipher Execution Guide
This repository provides instructions for running and analyzing various ciphers: GrainSoft-HMAC, Grain128 AEAD, Salsa20, and ChaCha20. Follow the steps below based on the cipher you want to run.
Case 1: GrainSoft-HMAC or Grain128 AEAD

Navigate to the Desired Directory:

Move to the directory containing the cipher files for either GrainSoft-HMAC or Grain128 AEAD.


Running GrainSoft-HMAC:

Open two terminals in the GrainSoft directory.
In the first terminal, run the server:python server.py


In the second terminal, run the client:python client.py




Running Grain128 AEAD:

Open two terminals in the Grain128 AEAD directory.
In the first terminal, run the server:python server_automate.py


In the second terminal, run the client:python client_automate.py





Case 2: Salsa20 or ChaCha20

For Salsa20 or ChaCha20, execute the respective Python files directly to measure the execution time:
For Salsa20, run:python salsa20.py


For ChaCha20, run:python chacha20.py





Case 3: Cryptanalysis of GrainSoft-HMAC

Generate Keystream:

Run the cryptanalysis script to generate the keystream:python Grainsoft_cryptanalysis.py


This will create a keystreambits.txt file containing the keystream in bits format (no other string literals).


Move Keystream File:

Copy or move the keystreambits.txt file to the sage-test folder.


Set Up SageMath Environment:

Open the sage-test folder in an Ubuntu or WSL environment.
Ensure the SageMath library is installed. If not, install it using:sudo apt-get install sagemath




Run Cryptanalysis Tests:

Execute individual test scripts in the sage-test folder using SageMath:sage filename.py

Replace filename.py with the specific test script name.



Prerequisites

Python 3.x installed for running GrainSoft-HMAC, Grain128 AEAD, Salsa20, and ChaCha20 scripts.
SageMath installed for cryptanalysis in the sage-test folder.
Ubuntu or WSL environment for running SageMath scripts.

Notes

Ensure all Python scripts are executable and dependencies are installed.
For GrainSoft-HMAC and Grain128 AEAD, both server and client must be running simultaneously in separate terminals.
The keystreambits.txt file must contain only bit values (0s and 1s) for compatibility with SageMath scripts.

