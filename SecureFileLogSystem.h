#ifndef SECURE_FILE_LOG_SYSTEM_H
#define SECURE_FILE_LOG_SYSTEM_H

#include <string>
#include <memory>

// Forward declarations
class FileManager;
class LogManager;

class SecureFileLogSystem {
private:
    std::unique_ptr<FileManager> fileManager;
    std::unique_ptr<LogManager> logManager;
    bool isRunning;
    
public:
    SecureFileLogSystem(const std::string& storagePath = "./secure_files");
    ~SecureFileLogSystem();
    
    // System management
    bool initialize();
    void shutdown();
    bool isSystemRunning() const { return isRunning; }
    
    // File operations
    std::string storeFile(const std::string& sourcePath, const std::string& userId, 
                         const std::string& ipAddress, bool encrypt = false);
    bool retrieveFile(const std::string& fileId, const std::string& destinationPath, 
                     const std::string& userId, const std::string& ipAddress);
    bool deleteFile(const std::string& fileId, const std::string& userId, 
                   const std::string& ipAddress);
    
    // User operations
    bool registerUser(const std::string& userId, const std::string& username, 
                     const std::string& password);
    bool authenticateUser(const std::string& userId, const std::string& password);
    
    // System operations
    void runInteractiveMode();
    void runServerMode(int port = 8080);
    
    // Reporting
    void generateSecurityReport() const;
    void exportLogs(const std::string& outputPath) const;
    
private:
    // Helper methods
    void showMainMenu();
    void handleUserInput();
    void initializeElasticSearchIntegration();
};

#endif // SECURE_FILE_LOG_SYSTEM_H
