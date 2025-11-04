#include "../include/EncryptionManager.h"
#include "../include/HashManager.h"
#include <iostream>
#include <cassert>
#include <fstream>

int main() {
    std::cout << "Testing EncryptionManager..." << std::endl;
    
    // Test AES-256 encryption/decryption
    std::string plaintext = "This is a secret message!";
    std::string key = HashManager::computeSHA256("my_secret_key");
    
    // Ensure key is 32 bytes
    if (key.length() > 32) {
        key = key.substr(0, 32);
    }
    
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Key: " << key << std::endl;
    
    // Encrypt
    std::string ciphertext = EncryptionManager::encryptAES256(plaintext, key);
    std::cout << "Ciphertext: " << ciphertext << std::endl;
    
    // Decrypt
    std::string decrypted = EncryptionManager::decryptAES256(ciphertext, key);
    std::cout << "Decrypted: " << decrypted << std::endl;
    
    // Verify
    assert(plaintext == decrypted);
    std::cout << "Encryption/Decryption test: PASSED" << std::endl;
    
    // Test file encryption/decryption
    // Create a test file
    std::ofstream testFile("test_file.txt");
    testFile << "This is a test file for encryption.\nIt has multiple lines.\nAnd some special characters: !@#$%^&*()";
    testFile.close();
    
    // Encrypt the file
    std::string encryptionKey = EncryptionManager::generateRandomKey();
    bool encryptResult = EncryptionManager::encryptFileAES256("test_file.txt", "encrypted_test_file.txt", encryptionKey);
    std::cout << "File encryption: " << (encryptResult ? "PASSED" : "FAILED") << std::endl;
    
    // Decrypt the file
    bool decryptResult = EncryptionManager::decryptFileAES256("encrypted_test_file.txt", "decrypted_test_file.txt", encryptionKey);
    std::cout << "File decryption: " << (decryptResult ? "PASSED" : "FAILED") << std::endl;
    
    // Verify file contents
    if (decryptResult) {
        std::ifstream original("test_file.txt");
        std::ifstream decryptedFile("decrypted_test_file.txt");
        
        std::string originalContent((std::istreambuf_iterator<char>(original)),
                                   std::istreambuf_iterator<char>());
        std::string decryptedContent((std::istreambuf_iterator<char>(decryptedFile)),
                                    std::istreambuf_iterator<char>());
        
        assert(originalContent == decryptedContent);
        std::cout << "File content verification: PASSED" << std::endl;
    }
    
    // Clean up test files
    std::remove("test_file.txt");
    std::remove("encrypted_test_file.txt");
    std::remove("decrypted_test_file.txt");
    
    std::cout << "All EncryptionManager tests passed!" << std::endl;
    return 0;
}
