#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>

// Forward declarations
class FileEntity;

class DatabaseManager {
private:
    std::string dbPath;
    std::map<std::string, std::shared_ptr<FileEntity>> files; // fileId -> FileEntity
    std::mutex dbMutex;
    bool isInitialized;
    
public:
    DatabaseManager(const std::string& dbPath = "file_database.db");
    
    // Database operations
    bool initialize();
    bool save();
    bool load();
    
    // File operations
    bool addFile(std::shared_ptr<FileEntity> file);
    bool updateFile(std::shared_ptr<FileEntity> file);
    bool removeFile(const std::string& fileId);
    std::shared_ptr<FileEntity> getFile(const std::string& fileId);
    std::vector<std::shared_ptr<FileEntity>> getAllFiles();
    std::vector<std::shared_ptr<FileEntity>> searchFiles(const std::string& query);
    
    // File metadata operations
    bool updateFileHash(const std::string& fileId, const std::string& hash);
    bool updateFileEncryptionStatus(const std::string& fileId, bool isEncrypted);
    
    // Utility methods
    bool fileExists(const std::string& fileId);
    size_t getFileCount() const;
    
private:
    // Generate unique file ID
    std::string generateFileId();
    
    // Serialize FileEntity to string
    std::string serializeFile(std::shared_ptr<FileEntity> file);
    
    // Deserialize FileEntity from string
    std::shared_ptr<FileEntity> deserializeFile(const std::string& data);
};

#endif // DATABASE_MANAGER_H
