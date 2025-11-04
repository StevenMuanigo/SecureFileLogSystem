#ifndef HASH_MANAGER_H
#define HASH_MANAGER_H

#include <string>
#include <vector>

class HashManager {
public:
    // Compute SHA-256 hash of a string
    static std::string computeSHA256(const std::string& data);
    
    // Compute SHA-256 hash of a file
    static std::string computeFileSHA256(const std::string& filePath);
    
    // Verify SHA-256 hash of a string
    static bool verifySHA256(const std::string& data, const std::string& expectedHash);
    
    // Verify SHA-256 hash of a file
    static bool verifyFileSHA256(const std::string& filePath, const std::string& expectedHash);
    
    // Generate random salt
    static std::string generateSalt(size_t length = 32);
    
private:
    // Helper method to convert bytes to hex string
    static std::string bytesToHex(const unsigned char* data, size_t length);
};

#endif // HASH_MANAGER_H
