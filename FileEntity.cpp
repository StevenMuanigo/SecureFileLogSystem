#include "../include/FileEntity.h"
#include <iomanip>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <random>

FileEntity::FileEntity() : fileSize(0), isEncrypted(false) {
    // Generate a unique ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    id = "FILE_" + std::to_string(dis(gen));
    
    createdAt = std::chrono::system_clock::now();
    lastModified = createdAt;
}

FileEntity::FileEntity(const std::string& fileName, const std::string& filePath, const std::string& owner) 
    : fileName(fileName), filePath(filePath), owner(owner), fileSize(0), isEncrypted(false) {
    // Generate a unique ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    id = "FILE_" + std::to_string(dis(gen));
    
    // Determine file type from extension
    size_t dotPos = fileName.find_last_of('.');
    if (dotPos != std::string::npos) {
        fileType = fileName.substr(dotPos + 1);
        std::transform(fileType.begin(), fileType.end(), fileType.begin(), ::tolower);
    } else {
        fileType = "unknown";
    }
    
    createdAt = std::chrono::system_clock::now();
    lastModified = createdAt;
}

std::string FileEntity::getFormattedCreationTime() const {
    auto time_t = std::chrono::system_clock::to_time_t(createdAt);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string FileEntity::getFormattedModificationTime() const {
    auto time_t = std::chrono::system_clock::to_time_t(lastModified);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool FileEntity::isValid() const {
    return !id.empty() && !fileName.empty() && !filePath.empty() && !owner.empty();
}
