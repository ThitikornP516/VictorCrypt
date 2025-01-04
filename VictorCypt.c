#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

void encrypt_file_aes(const char *input_file, const char *output_file, const unsigned char *key);
void decrypt_file_aes(const char *input_file, const char *output_file, const unsigned char *key);
void encrypt_file_chacha20(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *nonce);
void decrypt_file_chacha20(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *nonce);
void encrypt_file_hybrid(const char *input_file, const char *output_file, const char *rsa_public_key_file);
void decrypt_file_hybrid(const char *input_file, const char *output_file, const char *rsa_private_key_file);

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <mode> <input_file> <output_file>\n", argv[0]);
        fprintf(stderr, "Modes: encrypt-aes, decrypt-aes, encrypt-chacha20, decrypt-chacha20, encrypt-hybrid, decrypt-hybrid\n");
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];

    unsigned char key[AES_KEY_SIZE];
    unsigned char nonce[CHACHA20_NONCE_SIZE];

    if (strcmp(mode, "encrypt-aes") == 0) {
        if (!RAND_bytes(key, sizeof(key))) {
            fprintf(stderr, "Error generating AES key\n");
            return EXIT_FAILURE;
        }
        encrypt_file_aes(input_file, output_file, key);
        FILE *key_file = fopen("aes_key.bin", "wb");
        fwrite(key, 1, AES_KEY_SIZE, key_file);
        fclose(key_file);
    }
    else if (strcmp(mode, "decrypt-aes") == 0) {
        FILE *key_file = fopen("aes_key.bin", "rb");
        fread(key, 1, AES_KEY_SIZE, key_file);
        fclose(key_file);
        decrypt_file_aes(input_file, output_file, key);
    }
    else if (strcmp(mode, "encrypt-chacha20") == 0) {
        if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(nonce, sizeof(nonce))) {
            fprintf(stderr, "Error generating ChaCha20 key or nonce\n");
            return EXIT_FAILURE;
        }
        encrypt_file_chacha20(input_file, output_file, key, nonce);
        FILE *key_file = fopen("chacha20_key.bin", "wb");
        fwrite(key, 1, CHACHA20_KEY_SIZE, key_file);
        fclose(key_file);
        FILE *nonce_file = fopen("chacha20_nonce.bin", "wb");
        fwrite(nonce, 1, CHACHA20_NONCE_SIZE, nonce_file);
        fclose(nonce_file);
    }
    else if (strcmp(mode, "decrypt-chacha20") == 0) {
        FILE *key_file = fopen("chacha20_key.bin", "rb");
        fread(key, 1, CHACHA20_KEY_SIZE, key_file);
        fclose(key_file);
        FILE *nonce_file = fopen("chacha20_nonce.bin", "rb");
        fread(nonce, 1, CHACHA20_NONCE_SIZE, nonce_file);
        fclose(nonce_file);
        decrypt_file_chacha20(input_file, output_file, key, nonce);
    }
    else if (strcmp(mode, "encrypt-hybrid") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s encrypt-hybrid <input_file> <output_file> <rsa_public_key>\n", argv[0]);
            return EXIT_FAILURE;
        }
        encrypt_file_hybrid(input_file, output_file, argv[4]);
    }
    else if (strcmp(mode, "decrypt-hybrid") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Usage: %s decrypt-hybrid <input_file> <output_file> <rsa_private_key>\n", argv[0]);
            return EXIT_FAILURE;
        }
        decrypt_file_hybrid(input_file, output_file, argv[4]);
    }

    else {
        fprintf(stderr, "Invalid mode\n");
        return EXIT_FAILURE;
    }

    printf("Operation completed successfully!\n");
    return EXIT_SUCCESS;
}

void encrypt_file_aes(const char *input_file, const char *output_file, const unsigned char *key) {
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating IV\n");
        exit(EXIT_FAILURE);
    }

    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    fwrite(iv, 1, AES_BLOCK_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1024];
    unsigned char cipher[1040];
    int len, cipher_len;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_EncryptUpdate(ctx, cipher, &cipher_len, buffer, len);
        fwrite(cipher, 1, cipher_len, out);
    }

    EVP_EncryptFinal_ex(ctx, cipher, &cipher_len);
    fwrite(cipher, 1, cipher_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void decrypt_file_aes(const char *input_file, const char *output_file, const unsigned char *key) {
    unsigned char iv[AES_BLOCK_SIZE];

    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    fread(iv, 1, AES_BLOCK_SIZE, in);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1040];
    unsigned char plain[1024];
    int len, plain_len;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_DecryptUpdate(ctx, plain, &plain_len, buffer, len);
        fwrite(plain, 1, plain_len, out);
    }

    EVP_DecryptFinal_ex(ctx, plain, &plain_len);
    fwrite(plain, 1, plain_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void encrypt_file_chacha20(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *nonce) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    fwrite(nonce, 1, CHACHA20_NONCE_SIZE, out);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);

    unsigned char buffer[1024];
    unsigned char cipher[1024];
    int len, cipher_len;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_EncryptUpdate(ctx, cipher, &cipher_len, buffer, len);
        fwrite(cipher, 1, cipher_len, out);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void decrypt_file_chacha20(const char *input_file, const char *output_file, const unsigned char *key, const unsigned char *nonce) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    fread(nonce, 1, CHACHA20_NONCE_SIZE, in);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);

    unsigned char buffer[1024];
    unsigned char plain[1024];
    int len, plain_len;

    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_DecryptUpdate(ctx, plain, &plain_len, buffer, len);
        fwrite(plain, 1, plain_len, out);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void encrypt_file_hybrid(const char *input_file, const char *output_file, const char *rsa_public_key_file) {
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating AES key/IV\n");
        exit(EXIT_FAILURE);
    }

    // Load RSA public key
    FILE *pub_key_file = fopen(rsa_public_key_file, "rb");
    RSA *rsa_pub_key = PEM_read_RSA_PUBKEY(pub_key_file, NULL, NULL, NULL);
    fclose(pub_key_file);
    if (!rsa_pub_key) {
        fprintf(stderr, "Error loading RSA public key\n");
        exit(EXIT_FAILURE);
    }

    // Encrypt AES key using RSA
    unsigned char encrypted_key[RSA_size(rsa_pub_key)];
    int encrypted_key_len = RSA_public_encrypt(sizeof(key), key, encrypted_key, rsa_pub_key, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa_pub_key);
    if (encrypted_key_len == -1) {
        fprintf(stderr, "Error encrypting AES key with RSA\n");
        exit(EXIT_FAILURE);
    }

    // Write encrypted key and IV to output file
    FILE *out = fopen(output_file, "wb");
    fwrite(&encrypted_key_len, sizeof(encrypted_key_len), 1, out);
    fwrite(encrypted_key, 1, encrypted_key_len, out);
    fwrite(iv, 1, AES_BLOCK_SIZE, out);

    // Encrypt file using AES
    FILE *in = fopen(input_file, "rb");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1024];
    unsigned char cipher[1040];
    int len, cipher_len;
    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_EncryptUpdate(ctx, cipher, &cipher_len, buffer, len);
        fwrite(cipher, 1, cipher_len, out);
    }
    EVP_EncryptFinal_ex(ctx, cipher, &cipher_len);
    fwrite(cipher, 1, cipher_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

void decrypt_file_hybrid(const char *input_file, const char *output_file, const char *rsa_private_key_file) {
    // Load RSA private key
    FILE *priv_key_file = fopen(rsa_private_key_file, "rb");
    RSA *rsa_priv_key = PEM_read_RSAPrivateKey(priv_key_file, NULL, NULL, NULL);
    fclose(priv_key_file);
    if (!rsa_priv_key) {
        fprintf(stderr, "Error loading RSA private key\n");
        exit(EXIT_FAILURE);
    }

    // Read encrypted key and IV
    FILE *in = fopen(input_file, "rb");
    int encrypted_key_len;
    fread(&encrypted_key_len, sizeof(encrypted_key_len), 1, in);
    unsigned char encrypted_key[encrypted_key_len];
    fread(encrypted_key, 1, encrypted_key_len, in);
    unsigned char iv[AES_BLOCK_SIZE];
    fread(iv, 1, AES_BLOCK_SIZE, in);

    // Decrypt AES key
    unsigned char key[AES_KEY_SIZE];
    if (RSA_private_decrypt(encrypted_key_len, encrypted_key, key, rsa_priv_key, RSA_PKCS1_OAEP_PADDING) == -1) {
        fprintf(stderr, "Error decrypting AES key with RSA\n");
        RSA_free(rsa_priv_key);
        exit(EXIT_FAILURE);
    }
    RSA_free(rsa_priv_key);

    // Decrypt file using AES
    FILE *out = fopen(output_file, "wb");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char buffer[1040];
    unsigned char plain[1024];
    int len, plain_len;
    while ((len = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        EVP_DecryptUpdate(ctx, plain, &plain_len, buffer, len);
        fwrite(plain, 1, plain_len, out);
    }
    EVP_DecryptFinal_ex(ctx, plain, &plain_len);
    fwrite(plain, 1, plain_len, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
}

