#include "../include/FileManager.h"
#include "../include/FileEntity.h"
#include "../include/HashManager.h"
#include "../include/EncryptionManager.h"
#include "../include/LogManager.h"
#include "../include/AccessControl.h"
#include "../include/DatabaseManager.h"
#include <fstream>
#include <filesystem>
#include <iostream>

FileManager::FileManager(const std::string& storagePath) 
    : storagePath(storagePath) {
    // Create storage directory if it doesn't exist
    std::filesystem::create_directories(storagePath);
    
    // Initialize components
    hashManager = std::make_unique<HashManager>();
    encryptionManager = std::make_unique<EncryptionManager>();
    logManager = std::make_unique<LogManager>("file_access.log");
    accessControl = std::make_unique<AccessControl>();
    databaseManager = std::make_unique<DatabaseManager>("file_database.db");
    
    // Initialize database
    databaseManager->initialize();
}

std::string FileManager::storeFile(const std::string& sourcePath, const std::string& userId, 
                                  const std::string& ipAddress, bool encrypt) {
    // Check if source file exists
    if (!std::filesystem::exists(sourcePath)) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Attempt to store non-existent file: " + sourcePath, userId);
        return "";
    }
    
    // Create FileEntity
    std::string fileName = std::filesystem::path(sourcePath).filename().string();
    auto file = std::make_shared<FileEntity>(fileName, sourcePath, userId);
    
    // Set file size
    file->setFileSize(std::filesystem::file_size(sourcePath));
    
    // Compute SHA-256 hash
    std::string hash = HashManager::computeFileSHA256(sourcePath);
    file->setSha256Hash(hash);
    
    // Generate secure file path
    std::string secureFileName = file->getId() + "_" + fileName;
    std::string secureFilePath = storagePath + "/" + secureFileName;
    
    // Copy file to secure location
    try {
        if (encrypt) {
            // Encrypt file
            std::string encryptionKey = generateEncryptionKey(userId);
            if (!EncryptionManager::encryptFileAES256(sourcePath, secureFilePath, encryptionKey)) {
                logManager->logSecurityEvent("ENCRYPTION_FAILED", "Failed to encrypt file: " + sourcePath, userId);
                return "";
            }
            file->setIsEncrypted(true);
        } else {
            // Copy file without encryption
            std::filesystem::copy_file(sourcePath, secureFilePath);
            file->setIsEncrypted(false);
        }
        
        // Update file path
        file->setFilePath(secureFilePath);
        
        // Store file metadata in database
        databaseManager->addFile(file);
        
        // Log the operation
        logManager->logFileAccess(userId, fileName, ipAddress, "STORE");
        
        return file->getId();
    } catch (const std::exception& e) {
        logManager->logSecurityEvent("FILE_STORE_ERROR", "Error storing file: " + std::string(e.what()), userId);
        return "";
    }
}

bool FileManager::retrieveFile(const std::string& fileId, const std::string& destinationPath, 
                              const std::string& userId, const std::string& ipAddress) {
    // Check permissions
    if (!hasReadPermission(userId, fileId)) {
        logManager->logSecurityEvent("ACCESS_DENIED", "Unauthorized access attempt to file: " + fileId, userId);
        return false;
    }
    
    // Get file metadata
    auto file = databaseManager->getFile(fileId);
    if (!file) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Attempt to retrieve non-existent file: " + fileId, userId);
        return false;
    }
    
    // Check if secure file exists
    if (!std::filesystem::exists(file->getFilePath())) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Secure file not found: " + file->getFilePath(), userId);
        return false;
    }
    
    try {
        if (file->getIsEncrypted()) {
            // Decrypt file
            std::string encryptionKey = generateEncryptionKey(userId);
            if (!EncryptionManager::decryptFileAES256(file->getFilePath(), destinationPath, encryptionKey)) {
                logManager->logSecurityEvent("DECRYPTION_FAILED", "Failed to decrypt file: " + fileId, userId);
                return false;
            }
        } else {
            // Copy file without decryption
            std::filesystem::copy_file(file->getFilePath(), destinationPath);
        }
        
        // Log the operation
        logManager->logFileAccess(userId, file->getFileName(), ipAddress, "RETRIEVE");
        
        return true;
    } catch (const std::exception& e) {
        logManager->logSecurityEvent("FILE_RETRIEVE_ERROR", "Error retrieving file: " + std::string(e.what()), userId);
        return false;
    }
}

bool FileManager::deleteFile(const std::string& fileId, const std::string& userId, 
                            const std::string& ipAddress) {
    // Check permissions
    if (!hasDeletePermission(userId, fileId)) {
        logManager->logSecurityEvent("ACCESS_DENIED", "Unauthorized delete attempt for file: " + fileId, userId);
        return false;
    }
    
    // Get file metadata
    auto file = databaseManager->getFile(fileId);
    if (!file) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Attempt to delete non-existent file: " + fileId, userId);
        return false;
    }
    
    try {
        // Delete secure file
        if (std::filesystem::exists(file->getFilePath())) {
            std::filesystem::remove(file->getFilePath());
        }
        
        // Remove from database
        databaseManager->removeFile(fileId);
        
        // Log the operation
        logManager->logFileAccess(userId, file->getFileName(), ipAddress, "DELETE");
        
        return true;
    } catch (const std::exception& e) {
        logManager->logSecurityEvent("FILE_DELETE_ERROR", "Error deleting file: " + std::string(e.what()), userId);
        return false;
    }
}

std::shared_ptr<FileEntity> FileManager::getFileMetadata(const std::string& fileId, 
                                                        const std::string& userId, 
                                                        const std::string& ipAddress) {
    // Check permissions
    if (!hasReadPermission(userId, fileId)) {
        logManager->logSecurityEvent("ACCESS_DENIED", "Unauthorized metadata access for file: " + fileId, userId);
        return nullptr;
    }
    
    // Get file metadata
    auto file = databaseManager->getFile(fileId);
    if (!file) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Attempt to access metadata of non-existent file: " + fileId, userId);
        return nullptr;
    }
    
    // Log the operation
    logManager->logFileAccess(userId, file->getFileName(), ipAddress, "METADATA_ACCESS");
    
    return file;
}

std::vector<std::shared_ptr<FileEntity>> FileManager::listFiles(const std::string& userId) {
    // In a real implementation, this would filter files based on user permissions
    // For now, we'll return all files
    return databaseManager->getAllFiles();
}

bool FileManager::updateFileMetadata(const std::string& fileId, 
                                    const std::string& userId, 
                                    const std::string& ipAddress,
                                    const std::string& newFileName) {
    // Check permissions
    if (!hasWritePermission(userId, fileId)) {
        logManager->logSecurityEvent("ACCESS_DENIED", "Unauthorized metadata update for file: " + fileId, userId);
        return false;
    }
    
    // Get file metadata
    auto file = databaseManager->getFile(fileId);
    if (!file) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Attempt to update metadata of non-existent file: " + fileId, userId);
        return false;
    }
    
    // Update metadata
    if (!newFileName.empty()) {
        file->setFileName(newFileName);
    }
    
    file->setLastModified(std::chrono::system_clock::now());
    
    // Save updated metadata
    bool result = databaseManager->updateFile(file);
    
    if (result) {
        // Log the operation
        logManager->logFileAccess(userId, file->getFileName(), ipAddress, "METADATA_UPDATE");
    }
    
    return result;
}

bool FileManager::verifyFileIntegrity(const std::string& fileId) {
    // Get file metadata
    auto file = databaseManager->getFile(fileId);
    if (!file) {
        return false;
    }
    
    // Check if secure file exists
    if (!std::filesystem::exists(file->getFilePath())) {
        return false;
    }
    
    // Compute current hash
    std::string currentHash = HashManager::computeFileSHA256(file->getFilePath());
    
    // Compare with stored hash
    return currentHash == file->getSha256Hash();
}

bool FileManager::reEncryptFile(const std::string& fileId, const std::string& userId, 
                               const std::string& ipAddress) {
    // Check permissions
    if (!hasWritePermission(userId, fileId)) {
        logManager->logSecurityEvent("ACCESS_DENIED", "Unauthorized re-encryption attempt for file: " + fileId, userId);
        return false;
    }
    
    // Get file metadata
    auto file = databaseManager->getFile(fileId);
    if (!file) {
        logManager->logSecurityEvent("FILE_NOT_FOUND", "Attempt to re-encrypt non-existent file: " + fileId, userId);
        return false;
    }
    
    // Check if file is already encrypted
    if (!file->getIsEncrypted()) {
        logManager->logSecurityEvent("ENCRYPTION_ERROR", "Attempt to re-encrypt non-encrypted file: " + fileId, userId);
        return false;
    }
    
    try {
        // Generate new encryption key
        std::string newEncryptionKey = generateEncryptionKey(userId);
        
        // Create temporary file path
        std::string tempPath = file->getFilePath() + ".tmp";
        
        // Decrypt with old key and encrypt with new key
        std::string oldEncryptionKey = generateEncryptionKey(userId + "_old"); // This is simplified
        if (!EncryptionManager::decryptFileAES256(file->getFilePath(), tempPath, oldEncryptionKey)) {
            logManager->logSecurityEvent("DECRYPTION_FAILED", "Failed to decrypt file for re-encryption: " + fileId, userId);
            return false;
        }
        
        // Encrypt with new key
        if (!EncryptionManager::encryptFileAES256(tempPath, file->getFilePath(), newEncryptionKey)) {
            logManager->logSecurityEvent("ENCRYPTION_FAILED", "Failed to encrypt file during re-encryption: " + fileId, userId);
            std::filesystem::remove(tempPath);
            return false;
        }
        
        // Remove temporary file
        std::filesystem::remove(tempPath);
        
        // Log the operation
        logManager->logFileAccess(userId, file->getFileName(), ipAddress, "REENCRYPT");
        
        return true;
    } catch (const std::exception& e) {
        logManager->logSecurityEvent("REENCRYPTION_ERROR", "Error during re-encryption: " + std::string(e.what()), userId);
        return false;
    }
}

bool FileManager::registerUser(const std::string& userId, const std::string& username, 
                              const std::string& password) {
    return accessControl->addUser(userId, username, password);
}

bool FileManager::authenticateUser(const std::string& userId, const std::string& password) {
    return accessControl->authenticateUser(userId, password);
}

bool FileManager::isInitialized() const {
    return databaseManager && databaseManager->getFileCount() >= 0;
}

std::string FileManager::generateEncryptionKey(const std::string& userId) {
    // In a real implementation, this would generate a secure key based on user credentials
    // For now, we'll use a simple approach
    return HashManager::computeSHA256(userId + "_encryption_key");
}

bool FileManager::hasReadPermission(const std::string& userId, const std::string& fileId) {
    // In a real implementation, this would check actual permissions
    // For now, we'll allow read access to all authenticated users
    return !userId.empty();
}

bool FileManager::hasWritePermission(const std::string& userId, const std::string& fileId) {
    // In a real implementation, this would check actual permissions
    // For now, we'll allow write access to all authenticated users
    return !userId.empty();
}

bool FileManager::hasDeletePermission(const std::string& userId, const std::string& fileId) {
    // In a real implementation, this would check actual permissions
    // For now, we'll allow delete access to all authenticated users
    return !userId.empty();
}
