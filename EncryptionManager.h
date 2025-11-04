#ifndef ENCRYPTION_MANAGER_H
#define ENCRYPTION_MANAGER_H

#include <string>
#include <vector>

class EncryptionManager {
public:
    // Encrypt data using AES-256
    static std::string encryptAES256(const std::string& plaintext, const std::string& key);
    
    // Decrypt data using AES-256
    static std::string decryptAES256(const std::string& ciphertext, const std::string& key);
    
    // Encrypt file using AES-256
    static bool encryptFileAES256(const std::string& inputPath, const std::string& outputPath, const std::string& key);
    
    // Decrypt file using AES-256
    static bool decryptFileAES256(const std::string& inputPath, const std::string& outputPath, const std::string& key);
    
    // Generate AES-256 key from password
    static std::string generateKeyFromPassword(const std::string& password, const std::string& salt);
    
    // Generate random AES-256 key
    static std::string generateRandomKey();
    
private:
    // Helper methods
    static std::string bytesToHex(const unsigned char* data, size_t length);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);
};

#endif // ENCRYPTION_MANAGER_H
