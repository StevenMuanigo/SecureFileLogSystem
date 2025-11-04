#include "../include/SecureFileLogSystem.h"
#include <iostream>
#include <string>

int main() {
    std::cout << "Secure File & Log Management System" << std::endl;
    std::cout << "===================================" << std::endl;
    
    // Create and initialize the system
    auto system = std::make_unique<SecureFileLogSystem>("./secure_storage");
    
    if (!system->initialize()) {
        std::cerr << "Failed to initialize the system!" << std::endl;
        return 1;
    }
    
    std::cout << "System initialized successfully." << std::endl;
    
    // Register a sample user
    if (system->registerUser("admin", "Administrator", "admin123")) {
        std::cout << "Sample user 'admin' registered successfully." << std::endl;
    }
    
    // Initialize ElasticSearch integration
    system->initializeElasticSearchIntegration();
    
    // Run in interactive mode
    system->runInteractiveMode();
    
    // Shutdown system
    system->shutdown();
    
    std::cout << "System shutdown complete." << std::endl;
    return 0;
}
