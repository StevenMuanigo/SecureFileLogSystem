#ifndef FILE_ENTITY_H
#define FILE_ENTITY_H

#include <string>
#include <vector>
#include <chrono>

class FileEntity {
private:
    std::string id;
    std::string fileName;
    std::string filePath;
    std::string fileType;
    size_t fileSize;
    std::string sha256Hash;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastModified;
    bool isEncrypted;
    std::string owner;

public:
    FileEntity();
    FileEntity(const std::string& fileName, const std::string& filePath, const std::string& owner);
    
    // Getters
    std::string getId() const { return id; }
    std::string getFileName() const { return fileName; }
    std::string getFilePath() const { return filePath; }
    std::string getFileType() const { return fileType; }
    size_t getFileSize() const { return fileSize; }
    std::string getSha256Hash() const { return sha256Hash; }
    std::chrono::system_clock::time_point getCreatedAt() const { return createdAt; }
    std::chrono::system_clock::time_point getLastModified() const { return lastModified; }
    bool getIsEncrypted() const { return isEncrypted; }
    std::string getOwner() const { return owner; }
    
    // Setters
    void setId(const std::string& id) { this->id = id; }
    void setFileName(const std::string& fileName) { this->fileName = fileName; }
    void setFilePath(const std::string& filePath) { this->filePath = filePath; }
    void setFileType(const std::string& fileType) { this->fileType = fileType; }
    void setFileSize(size_t fileSize) { this->fileSize = fileSize; }
    void setSha256Hash(const std::string& hash) { this->sha256Hash = hash; }
    void setCreatedAt(const std::chrono::system_clock::time_point& time) { this->createdAt = time; }
    void setLastModified(const std::chrono::system_clock::time_point& time) { this->lastModified = time; }
    void setIsEncrypted(bool encrypted) { this->isEncrypted = encrypted; }
    void setOwner(const std::string& owner) { this->owner = owner; }
    
    // Utility methods
    std::string getFormattedCreationTime() const;
    std::string getFormattedModificationTime() const;
    bool isValid() const;
};

#endif // FILE_ENTITY_H
