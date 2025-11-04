#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <string>
#include <vector>
#include <memory>

// Forward declarations
class FileEntity;
class HashManager;
class EncryptionManager;
class LogManager;
class AccessControl;
class DatabaseManager;

class FileManager {
private:
    std::string storagePath;
    std::unique_ptr<HashManager> hashManager;
    std::unique_ptr<EncryptionManager> encryptionManager;
    std::unique_ptr<LogManager> logManager;
    std::unique_ptr<AccessControl> accessControl;
    std::unique_ptr<DatabaseManager> databaseManager;
    
public:
    FileManager(const std::string& storagePath = "./secure_files");
    
    // File operations
    std::string storeFile(const std::string& sourcePath, const std::string& userId, 
                         const std::string& ipAddress, bool encrypt = false);
    bool retrieveFile(const std::string& fileId, const std::string& destinationPath, 
                     const std::string& userId, const std::string& ipAddress);
    bool deleteFile(const std::string& fileId, const std::string& userId, 
                   const std::string& ipAddress);
    
    // File management
    std::shared_ptr<FileEntity> getFileMetadata(const std::string& fileId, 
                                               const std::string& userId, 
                                               const std::string& ipAddress);
    std::vector<std::shared_ptr<FileEntity>> listFiles(const std::string& userId);
    bool updateFileMetadata(const std::string& fileId, 
                           const std::string& userId, 
                           const std::string& ipAddress,
                           const std::string& newFileName = "");
    
    // Security operations
    bool verifyFileIntegrity(const std::string& fileId);
    bool reEncryptFile(const std::string& fileId, const std::string& userId, 
                      const std::string& ipAddress);
    
    // User operations
    bool registerUser(const std::string& userId, const std::string& username, 
                     const std::string& password);
    bool authenticateUser(const std::string& userId, const std::string& password);
    
    // Utility methods
    std::string getStoragePath() const { return storagePath; }
    bool isInitialized() const;
    
private:
    // Helper methods
    std::string generateEncryptionKey(const std::string& userId);
    bool hasReadPermission(const std::string& userId, const std::string& fileId);
    bool hasWritePermission(const std::string& userId, const std::string& fileId);
    bool hasDeletePermission(const std::string& userId, const std::string& fileId);
};

#endif // FILE_MANAGER_H
