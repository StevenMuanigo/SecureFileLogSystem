#include "../include/EncryptionManager.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <random>

std::string EncryptionManager::encryptAES256(const std::string& plaintext, const std::string& key) {
    // Ensure key is 32 bytes (256 bits)
    std::string derivedKey = key;
    if (derivedKey.length() < 32) {
        // Pad with zeros if too short
        derivedKey.resize(32, '\0');
    } else if (derivedKey.length() > 32) {
        // Truncate if too long
        derivedKey = derivedKey.substr(0, 32);
    }
    
    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    
    // Encrypt the data
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                       reinterpret_cast<const unsigned char*>(derivedKey.c_str()), iv);
    
    std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len;
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                      reinterpret_cast<const unsigned char*>(plaintext.c_str()), 
                      plaintext.length());
    ciphertext_len = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
    std::vector<unsigned char> result;
    result.insert(result.end(), iv, iv + AES_BLOCK_SIZE);
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    
    return bytesToHex(result.data(), result.size());
}

std::string EncryptionManager::decryptAES256(const std::string& ciphertext, const std::string& key) {
    // Ensure key is 32 bytes (256 bits)
    std::string derivedKey = key;
    if (derivedKey.length() < 32) {
        // Pad with zeros if too short
        derivedKey.resize(32, '\0');
    } else if (derivedKey.length() > 32) {
        // Truncate if too long
        derivedKey = derivedKey.substr(0, 32);
    }
    
    // Convert hex string to bytes
    std::vector<unsigned char> data = hexToBytes(ciphertext);
    
    if (data.size() < AES_BLOCK_SIZE) {
        return ""; // Invalid data
    }
    
    // Extract IV and ciphertext
    unsigned char* iv = data.data();
    unsigned char* encrypted_data = data.data() + AES_BLOCK_SIZE;
    int encrypted_len = data.size() - AES_BLOCK_SIZE;
    
    // Decrypt the data
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       reinterpret_cast<const unsigned char*>(derivedKey.c_str()), iv);
    
    std::vector<unsigned char> plaintext(encrypted_len + AES_BLOCK_SIZE);
    int len;
    int plaintext_len;
    
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data, encrypted_len);
    plaintext_len = len;
    
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

bool EncryptionManager::encryptFileAES256(const std::string& inputPath, const std::string& outputPath, const std::string& key) {
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        return false;
    }
    
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile) {
        return false;
    }
    
    // Ensure key is 32 bytes (256 bits)
    std::string derivedKey = key;
    if (derivedKey.length() < 32) {
        derivedKey.resize(32, '\0');
    } else if (derivedKey.length() > 32) {
        derivedKey = derivedKey.substr(0, 32);
    }
    
    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    
    // Write IV to output file
    outputFile.write(reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);
    
    // Encrypt the file
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       reinterpret_cast<const unsigned char*>(derivedKey.c_str()), iv);
    
    char buffer[8192];
    unsigned char ciphertext[8192 + AES_BLOCK_SIZE];
    int len;
    
    while (inputFile.read(buffer, sizeof(buffer)) || inputFile.gcount() > 0) {
        EVP_EncryptUpdate(ctx, ciphertext, &len,
                          reinterpret_cast<const unsigned char*>(buffer), 
                          inputFile.gcount());
        outputFile.write(reinterpret_cast<const char*>(ciphertext), len);
    }
    
    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext, &len);
    outputFile.write(reinterpret_cast<const char*>(ciphertext), len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
}

bool EncryptionManager::decryptFileAES256(const std::string& inputPath, const std::string& outputPath, const std::string& key) {
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        return false;
    }
    
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile) {
        return false;
    }
    
    // Ensure key is 32 bytes (256 bits)
    std::string derivedKey = key;
    if (derivedKey.length() < 32) {
        derivedKey.resize(32, '\0');
    } else if (derivedKey.length() > 32) {
        derivedKey = derivedKey.substr(0, 32);
    }
    
    // Read IV from input file
    unsigned char iv[AES_BLOCK_SIZE];
    inputFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    
    // Decrypt the file
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                       reinterpret_cast<const unsigned char*>(derivedKey.c_str()), iv);
    
    char buffer[8192 + AES_BLOCK_SIZE];
    unsigned char plaintext[8192 + AES_BLOCK_SIZE];
    int len;
    
    while (inputFile.read(buffer, sizeof(buffer)) || inputFile.gcount() > 0) {
        EVP_DecryptUpdate(ctx, plaintext, &len,
                          reinterpret_cast<const unsigned char*>(buffer), 
                          inputFile.gcount());
        outputFile.write(reinterpret_cast<const char*>(plaintext), len);
    }
    
    // Finalize decryption
    EVP_DecryptFinal_ex(ctx, plaintext, &len);
    outputFile.write(reinterpret_cast<const char*>(plaintext), len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return true;
}

std::string EncryptionManager::generateKeyFromPassword(const std::string& password, const std::string& salt) {
    unsigned char key[32]; // 256 bits
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
                      10000, EVP_sha256(), 32, key);
    
    return std::string(reinterpret_cast<char*>(key), 32);
}

std::string EncryptionManager::generateRandomKey() {
    unsigned char key[32];
    RAND_bytes(key, 32);
    return std::string(reinterpret_cast<char*>(key), 32);
}

std::string EncryptionManager::bytesToHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    
    return ss.str();
}

std::vector<unsigned char> EncryptionManager::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    
    return bytes;
}
