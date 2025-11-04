#include "../include/AccessControl.h"
#include "../include/HashManager.h"
#include <algorithm>

// User implementation
User::User(const std::string& userId, const std::string& username, const std::string& passwordHash)
    : userId(userId), username(username), passwordHash(passwordHash) {}

void User::removeRole(const std::string& role) {
    roles.erase(std::remove(roles.begin(), roles.end(), role), roles.end());
}

bool User::isValid() const {
    return !userId.empty() && !username.empty() && !passwordHash.empty();
}

// AccessControl implementation
AccessControl::AccessControl() {}

bool AccessControl::addUser(const std::string& userId, const std::string& username, const std::string& password) {
    // Check if user already exists
    if (users.find(userId) != users.end()) {
        return false;
    }
    
    // Hash the password
    std::string salt = HashManager::generateSalt();
    std::string hashedPassword = HashManager::computeSHA256(password + salt);
    
    // Create and store user
    auto user = std::make_shared<User>(userId, username, hashedPassword);
    users[userId] = user;
    
    return true;
}

bool AccessControl::removeUser(const std::string& userId) {
    auto it = users.find(userId);
    if (it == users.end()) {
        return false;
    }
    
    users.erase(it);
    return true;
}

std::shared_ptr<User> AccessControl::getUser(const std::string& userId) {
    auto it = users.find(userId);
    if (it == users.end()) {
        return nullptr;
    }
    
    return it->second;
}

bool AccessControl::authenticateUser(const std::string& userId, const std::string& password) {
    auto user = getUser(userId);
    if (!user) {
        return false;
    }
    
    // In a real implementation, we would verify the password against the stored hash
    // For now, we'll just return true if the user exists
    return true;
}

bool AccessControl::grantPermission(const std::string& userId, const std::string& fileId, Permission permission) {
    // Check if user exists
    if (users.find(userId) == users.end()) {
        return false;
    }
    
    // Grant permission
    std::string key = fileId + ":" + userId;
    userPermissions[key] = userPermissions[key] | permission;
    
    // Add user to file permissions
    filePermissions[fileId].insert(userId);
    
    return true;
}

bool AccessControl::revokePermission(const std::string& userId, const std::string& fileId, Permission permission) {
    // Check if user exists
    if (users.find(userId) == users.end()) {
        return false;
    }
    
    // Revoke permission
    std::string key = fileId + ":" + userId;
    userPermissions[key] = userPermissions[key] & ~permission;
    
    return true;
}

bool AccessControl::hasPermission(const std::string& userId, const std::string& fileId, Permission permission) {
    // Check if user exists
    if (users.find(userId) == users.end()) {
        return false;
    }
    
    // Check permission
    std::string key = fileId + ":" + userId;
    return (userPermissions[key] & permission) == permission;
}

bool AccessControl::canReadFile(const std::string& userId, const std::string& fileId) {
    return hasPermission(userId, fileId, READ);
}

bool AccessControl::canWriteFile(const std::string& userId, const std::string& fileId) {
    return hasPermission(userId, fileId, WRITE);
}

bool AccessControl::canDeleteFile(const std::string& userId, const std::string& fileId) {
    return hasPermission(userId, fileId, DELETE);
}

bool AccessControl::isAdmin(const std::string& userId) {
    return hasPermission(userId, "", ADMIN);
}

bool AccessControl::assignRole(const std::string& userId, const std::string& role) {
    auto user = getUser(userId);
    if (!user) {
        return false;
    }
    
    user->addRole(role);
    return true;
}

bool AccessControl::hasRole(const std::string& userId, const std::string& role) {
    auto user = getUser(userId);
    if (!user) {
        return false;
    }
    
    const auto& roles = user->getRoles();
    return std::find(roles.begin(), roles.end(), role) != roles.end();
}

std::string AccessControl::hashPassword(const std::string& password) {
    // In a real implementation, we would use a proper password hashing algorithm like bcrypt
    // For now, we'll use SHA-256 with a salt
    std::string salt = HashManager::generateSalt();
    return HashManager::computeSHA256(password + salt);
}
