#include "../include/HashManager.h"
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>

std::string HashManager::computeSHA256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

std::string HashManager::computeFileSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return "";
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

bool HashManager::verifySHA256(const std::string& data, const std::string& expectedHash) {
    std::string computedHash = computeSHA256(data);
    return computedHash == expectedHash;
}

bool HashManager::verifyFileSHA256(const std::string& filePath, const std::string& expectedHash) {
    std::string computedHash = computeFileSHA256(filePath);
    return computedHash == expectedHash;
}

std::string HashManager::generateSalt(size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::vector<unsigned char> salt(length);
    for (size_t i = 0; i < length; ++i) {
        salt[i] = static_cast<unsigned char>(dis(gen));
    }
    
    return bytesToHex(salt.data(), salt.size());
}

std::string HashManager::bytesToHex(const unsigned char* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    
    return ss.str();
}
