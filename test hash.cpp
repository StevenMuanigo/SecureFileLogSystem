#include "../include/HashManager.h"
#include <iostream>
#include <cassert>

int main() {
    std::cout << "Testing HashManager..." << std::endl;
    
    // Test SHA-256 computation
    std::string testData = "Hello, World!";
    std::string hash = HashManager::computeSHA256(testData);
    
    std::cout << "Input: " << testData << std::endl;
    std::cout << "SHA-256: " << hash << std::endl;
    
    // Verify the hash
    bool verified = HashManager::verifySHA256(testData, hash);
    assert(verified);
    std::cout << "Hash verification: " << (verified ? "PASSED" : "FAILED") << std::endl;
    
    // Test salt generation
    std::string salt = HashManager::generateSalt();
    std::cout << "Generated salt: " << salt << std::endl;
    assert(salt.length() == 64); // 32 bytes = 64 hex characters
    
    std::cout << "All HashManager tests passed!" << std::endl;
    return 0;
}
