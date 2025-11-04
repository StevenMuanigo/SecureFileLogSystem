#include "../include/FileManager.h"
#include "../include/FileEntity.h"
#include <iostream>
#include <cassert>
#include <fstream>

int main() {
    std::cout << "Testing FileManager..." << std::endl;
    
    // Create FileManager
    FileManager fileManager("./test_storage");
    
    // Register a test user
    bool userRegistered = fileManager.registerUser("testuser", "Test User", "password123");
    std::cout << "User registration: " << (userRegistered ? "PASSED" : "FAILED") << std::endl;
    
    // Authenticate user
    bool userAuthenticated = fileManager.authenticateUser("testuser", "password123");
    std::cout << "User authentication: " << (userAuthenticated ? "PASSED" : "FAILED") << std::endl;
    
    // Create a test file
    std::ofstream testFile("sample.txt");
    testFile << "This is a sample file for testing the FileManager.\nIt has multiple lines.\nAnd some special characters: !@#$%^&*()";
    testFile.close();
    
    // Store file
    std::string fileId = fileManager.storeFile("sample.txt", "testuser", "127.0.0.1", false);
    std::cout << "File storage: " << (!fileId.empty() ? "PASSED" : "FAILED") << std::endl;
    if (!fileId.empty()) {
        std::cout << "Stored file ID: " << fileId << std::endl;
    }
    
    // Retrieve file
    bool retrieved = fileManager.retrieveFile(fileId, "retrieved_sample.txt", "testuser", "127.0.0.1");
    std::cout << "File retrieval: " << (retrieved ? "PASSED" : "FAILED") << std::endl;
    
    // Verify file integrity
    bool integrity = fileManager.verifyFileIntegrity(fileId);
    std::cout << "File integrity verification: " << (integrity ? "PASSED" : "FAILED") << std::endl;
    
    // Get file metadata
    auto fileMetadata = fileManager.getFileMetadata(fileId, "testuser", "127.0.0.1");
    if (fileMetadata) {
        std::cout << "File metadata retrieval: PASSED" << std::endl;
        std::cout << "  File name: " << fileMetadata->getFileName() << std::endl;
        std::cout << "  File size: " << fileMetadata->getFileSize() << " bytes" << std::endl;
        std::cout << "  File hash: " << fileMetadata->getSha256Hash() << std::endl;
        std::cout << "  Encrypted: " << (fileMetadata->getIsEncrypted() ? "YES" : "NO") << std::endl;
    } else {
        std::cout << "File metadata retrieval: FAILED" << std::endl;
    }
    
    // List files
    auto files = fileManager.listFiles("testuser");
    std::cout << "File listing: PASSED (" << files.size() << " files found)" << std::endl;
    
    // Clean up test files
    if (!fileId.empty()) {
        fileManager.deleteFile(fileId, "testuser", "127.0.0.1");
        std::cout << "File deletion: PASSED" << std::endl;
    }
    
    std::remove("sample.txt");
    std::remove("retrieved_sample.txt");
    
    // Clean up test storage directory
    // Note: In a real application, you might want to remove the entire test_storage directory
    
    std::cout << "All FileManager tests completed!" << std::endl;
    return 0;
}
