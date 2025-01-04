# VictorCrypt: A File Encryption Tool

VictorCrypt is a command-line tool designed to encrypt and decrypt files using AES, ChaCha20, and hybrid RSA-AES encryption techniques. It leverages OpenSSL for cryptographic operations, ensuring strong security.

## Features

- **AES Encryption**: File encryption and decryption using AES-256 in CBC mode.
- **ChaCha20 Encryption**: File encryption and decryption using the ChaCha20 stream cipher.
- **Hybrid RSA-AES Encryption**: Combines RSA public-key encryption with AES for secure key exchange and data encryption.
- **Random Key Generation**: Securely generates random keys and nonces for encryption.

## Prerequisites

- **OpenSSL**: Ensure OpenSSL is installed on your system.
- **C Compiler**: A C compiler like GCC to compile the program.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ThitikornP516/VictorCrypt.git
   cd VictorCrypt
   ```

2. Compile the program:
   ```bash
   gcc -o VictorCrypt VictorCrypt.c -lcrypto -lssl
   ```

## Usage

```bash
./VictorCrypt <mode> <input_file> <output_file> [key_file]
```

### Modes

1. **AES Encryption**:
   ```bash
   ./VictorCrypt encrypt-aes <input_file> <output_file>
   ```
   - Generates a random AES key and saves it to `aes_key.bin`.

2. **AES Decryption**:
   ```bash
   ./VictorCrypt decrypt-aes <input_file> <output_file>
   ```
   - Uses the key from `aes_key.bin` for decryption.

3. **ChaCha20 Encryption**:
   ```bash
   ./VictorCrypt encrypt-chacha20 <input_file> <output_file>
   ```
   - Generates a random ChaCha20 key and nonce, saving them to `chacha20_key.bin` and `chacha20_nonce.bin`.

4. **ChaCha20 Decryption**:
   ```bash
   ./VictorCrypt decrypt-chacha20 <input_file> <output_file>
   ```
   - Uses the key and nonce from `chacha20_key.bin` and `chacha20_nonce.bin`.

5. **Hybrid RSA-AES Encryption**:
   ```bash
   ./VictorCrypt encrypt-hybrid <input_file> <output_file> <rsa_public_key>
   ```
   - Encrypts the AES key using the provided RSA public key.

6. **Hybrid RSA-AES Decryption**:
   ```bash
   ./VictorCrypt decrypt-hybrid <input_file> <output_file> <rsa_private_key>
   ```
   - Decrypts the AES key using the provided RSA private key.

## File Structure

- `VictorCrypt.c`: Main source code.
- `aes_key.bin`: Stores the AES encryption key.
- `chacha20_key.bin`: Stores the ChaCha20 encryption key.
- `chacha20_nonce.bin`: Stores the ChaCha20 nonce.

## Security Notes

- Keep your key files (`aes_key.bin`, `chacha20_key.bin`, `chacha20_nonce.bin`, and RSA keys) secure.
- Do not share private keys or encryption keys publicly.
- Ensure that OpenSSL is up-to-date to prevent vulnerabilities.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you would like to contribute.

## Acknowledgments

- OpenSSL for cryptographic libraries.
- Inspiration from various encryption tools and techniques.

## Contact

For questions or feedback, please reach out at [thitikornphumma@gmail.com].

