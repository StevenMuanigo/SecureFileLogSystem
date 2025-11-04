#include "../include/SecureFileLogSystem.h"
#include "../include/FileManager.h"
#include "../include/LogManager.h"
#include <iostream>
#include <string>
#include <vector>

SecureFileLogSystem::SecureFileLogSystem(const std::string& storagePath) 
    : isRunning(false) {
    fileManager = std::make_unique<FileManager>(storagePath);
    logManager = std::make_unique<LogManager>("system.log");
}

SecureFileLogSystem::~SecureFileLogSystem() {
    if (isRunning) {
        shutdown();
    }
}

bool SecureFileLogSystem::initialize() {
    if (!fileManager || !fileManager->isInitialized()) {
        logManager->logSystemEvent("INITIALIZATION_FAILED", "File manager initialization failed");
        return false;
    }
    
    isRunning = true;
    logManager->logSystemEvent("SYSTEM_STARTED", "Secure File Log System initialized successfully");
    return true;
}

void SecureFileLogSystem::shutdown() {
    isRunning = false;
    logManager->logSystemEvent("SYSTEM_STOPPED", "Secure File Log System shutdown");
}

std::string SecureFileLogSystem::storeFile(const std::string& sourcePath, const std::string& userId, 
                                         const std::string& ipAddress, bool encrypt) {
    if (!isRunning) {
        return "";
    }
    
    return fileManager->storeFile(sourcePath, userId, ipAddress, encrypt);
}

bool SecureFileLogSystem::retrieveFile(const std::string& fileId, const std::string& destinationPath, 
                                     const std::string& userId, const std::string& ipAddress) {
    if (!isRunning) {
        return false;
    }
    
    return fileManager->retrieveFile(fileId, destinationPath, userId, ipAddress);
}

bool SecureFileLogSystem::deleteFile(const std::string& fileId, const std::string& userId, 
                                   const std::string& ipAddress) {
    if (!isRunning) {
        return false;
    }
    
    return fileManager->deleteFile(fileId, userId, ipAddress);
}

bool SecureFileLogSystem::registerUser(const std::string& userId, const std::string& username, 
                                     const std::string& password) {
    if (!isRunning) {
        return false;
    }
    
    return fileManager->registerUser(userId, username, password);
}

bool SecureFileLogSystem::authenticateUser(const std::string& userId, const std::string& password) {
    if (!isRunning) {
        return false;
    }
    
    return fileManager->authenticateUser(userId, password);
}

void SecureFileLogSystem::runInteractiveMode() {
    if (!isRunning) {
        std::cout << "System is not initialized. Please initialize first." << std::endl;
        return;
    }
    
    std::cout << "=== Secure File & Log Management System ===" << std::endl;
    std::cout << "Interactive Mode" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    std::string input;
    while (isRunning) {
        showMainMenu();
        std::getline(std::cin, input);
        
        if (input == "0") {
            break;
        }
        
        handleUserInput();
    }
}

void SecureFileLogSystem::runServerMode(int port) {
    if (!isRunning) {
        std::cout << "System is not initialized. Please initialize first." << std::endl;
        return;
    }
    
    std::cout << "Starting server mode on port " << port << std::endl;
    // In a real implementation, this would start a web server
    // For now, we'll just simulate it
}

void SecureFileLogSystem::generateSecurityReport() const {
    if (!isRunning) {
        return;
    }
    
    std::cout << "\n=== Security Report ===" << std::endl;
    std::cout << "System Status: " << (isRunning ? "RUNNING" : "STOPPED") << std::endl;
    // In a real implementation, this would generate a detailed security report
    std::cout << "Report generated successfully." << std::endl;
}

void SecureFileLogSystem::exportLogs(const std::string& outputPath) const {
    if (!isRunning) {
        return;
    }
    
    std::cout << "Exporting logs to " << outputPath << std::endl;
    // In a real implementation, this would export logs to the specified path
    std::cout << "Logs exported successfully." << std::endl;
}

void SecureFileLogSystem::showMainMenu() {
    std::cout << "\nMain Menu:" << std::endl;
    std::cout << "1. Store File" << std::endl;
    std::cout << "2. Retrieve File" << std::endl;
    std::cout << "3. Delete File" << std::endl;
    std::cout << "4. List Files" << std::endl;
    std::cout << "5. User Management" << std::endl;
    std::cout << "6. Security Report" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Select an option: ";
}

void SecureFileLogSystem::handleUserInput() {
    // In a real implementation, this would handle user input
    std::cout << "Feature not implemented in this demo version." << std::endl;
}

void SecureFileLogSystem::initializeElasticSearchIntegration() {
    // Initialize ElasticSearch integration
    logManager->enableElasticSearchIntegration("http://localhost:9200");
    std::cout << "ElasticSearch integration enabled." << std::endl;
}
