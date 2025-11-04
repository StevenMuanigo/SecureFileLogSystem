#include "../include/DatabaseManager.h"
#include "../include/FileEntity.h"
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <ctime>

DatabaseManager::DatabaseManager(const std::string& dbPath) 
    : dbPath(dbPath), isInitialized(false) {}

bool DatabaseManager::initialize() {
    // Create database file if it doesn't exist
    std::ifstream dbFile(dbPath);
    if (!dbFile.good()) {
        std::ofstream newDbFile(dbPath);
        if (!newDbFile) {
            return false;
        }
        newDbFile.close();
    }
    
    // Load existing data
    load();
    
    isInitialized = true;
    return true;
}

bool DatabaseManager::save() {
    std::lock_guard<std::mutex> lock(dbMutex);
    
    std::ofstream dbFile(dbPath);
    if (!dbFile) {
        return false;
    }
    
    // Serialize all files
    for (const auto& pair : files) {
        std::string serialized = serializeFile(pair.second);
        dbFile << serialized << std::endl;
    }
    
    return true;
}

bool DatabaseManager::load() {
    std::lock_guard<std::mutex> lock(dbMutex);
    
    std::ifstream dbFile(dbPath);
    if (!dbFile) {
        return false;
    }
    
    std::string line;
    while (std::getline(dbFile, line)) {
        auto file = deserializeFile(line);
        if (file && !file->getId().empty()) {
            files[file->getId()] = file;
        }
    }
    
    return true;
}

bool DatabaseManager::addFile(std::shared_ptr<FileEntity> file) {
    if (!file || file->getId().empty()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(dbMutex);
    files[file->getId()] = file;
    return save();
}

bool DatabaseManager::updateFile(std::shared_ptr<FileEntity> file) {
    if (!file || file->getId().empty()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(dbMutex);
    files[file->getId()] = file;
    return save();
}

bool DatabaseManager::removeFile(const std::string& fileId) {
    std::lock_guard<std::mutex> lock(dbMutex);
    auto it = files.find(fileId);
    if (it == files.end()) {
        return false;
    }
    
    files.erase(it);
    return save();
}

std::shared_ptr<FileEntity> DatabaseManager::getFile(const std::string& fileId) {
    std::lock_guard<std::mutex> lock(dbMutex);
    auto it = files.find(fileId);
    if (it == files.end()) {
        return nullptr;
    }
    
    return it->second;
}

std::vector<std::shared_ptr<FileEntity>> DatabaseManager::getAllFiles() {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<std::shared_ptr<FileEntity>> result;
    
    for (const auto& pair : files) {
        result.push_back(pair.second);
    }
    
    return result;
}

std::vector<std::shared_ptr<FileEntity>> DatabaseManager::searchFiles(const std::string& query) {
    std::lock_guard<std::mutex> lock(dbMutex);
    std::vector<std::shared_ptr<FileEntity>> result;
    
    for (const auto& pair : files) {
        auto file = pair.second;
        if (file->getFileName().find(query) != std::string::npos ||
            file->getFileType().find(query) != std::string::npos ||
            file->getOwner().find(query) != std::string::npos) {
            result.push_back(file);
        }
    }
    
    return result;
}

bool DatabaseManager::updateFileHash(const std::string& fileId, const std::string& hash) {
    auto file = getFile(fileId);
    if (!file) {
        return false;
    }
    
    file->setSha256Hash(hash);
    file->setLastModified(std::chrono::system_clock::now());
    return updateFile(file);
}

bool DatabaseManager::updateFileEncryptionStatus(const std::string& fileId, bool isEncrypted) {
    auto file = getFile(fileId);
    if (!file) {
        return false;
    }
    
    file->setIsEncrypted(isEncrypted);
    file->setLastModified(std::chrono::system_clock::now());
    return updateFile(file);
}

bool DatabaseManager::fileExists(const std::string& fileId) {
    std::lock_guard<std::mutex> lock(dbMutex);
    return files.find(fileId) != files.end();
}

size_t DatabaseManager::getFileCount() const {
    std::lock_guard<std::mutex> lock(dbMutex);
    return files.size();
}

std::string DatabaseManager::generateFileId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    return "FILE_" + std::to_string(dis(gen));
}

std::string DatabaseManager::serializeFile(std::shared_ptr<FileEntity> file) {
    if (!file) {
        return "";
    }
    
    std::stringstream ss;
    ss << file->getId() << "|"
       << file->getFileName() << "|"
       << file->getFilePath() << "|"
       << file->getFileType() << "|"
       << file->getFileSize() << "|"
       << file->getSha256Hash() << "|"
       << file->getOwner() << "|"
       << file->getIsEncrypted();
    
    return ss.str();
}

std::shared_ptr<FileEntity> DatabaseManager::deserializeFile(const std::string& data) {
    std::stringstream ss(data);
    std::string token;
    std::vector<std::string> tokens;
    
    while (std::getline(ss, token, '|')) {
        tokens.push_back(token);
    }
    
    if (tokens.size() < 8) {
        return nullptr;
    }
    
    auto file = std::make_shared<FileEntity>();
    file->setId(tokens[0]);
    file->setFileName(tokens[1]);
    file->setFilePath(tokens[2]);
    file->setFileType(tokens[3]);
    
    try {
        file->setFileSize(std::stoull(tokens[4]));
    } catch (...) {
        file->setFileSize(0);
    }
    
    file->setSha256Hash(tokens[5]);
    file->setOwner(tokens[6]);
    file->setIsEncrypted(tokens[7] == "1");
    
    return file;
}
