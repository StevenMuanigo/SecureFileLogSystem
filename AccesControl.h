#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <set>

// Forward declarations
class User;
class FileEntity;

class AccessControl {
public:
    enum Permission {
        READ = 1,
        WRITE = 2,
        DELETE = 4,
        ADMIN = 8
    };
    
private:
    std::map<std::string, std::shared_ptr<User>> users;
    std::map<std::string, std::set<std::string>> filePermissions; // fileId -> userIds
    std::map<std::string, int> userPermissions; // userId -> permissions bitmask
    
public:
    AccessControl();
    
    // User management
    bool addUser(const std::string& userId, const std::string& username, const std::string& password);
    bool removeUser(const std::string& userId);
    std::shared_ptr<User> getUser(const std::string& userId);
    bool authenticateUser(const std::string& userId, const std::string& password);
    
    // Permission management
    bool grantPermission(const std::string& userId, const std::string& fileId, Permission permission);
    bool revokePermission(const std::string& userId, const std::string& fileId, Permission permission);
    bool hasPermission(const std::string& userId, const std::string& fileId, Permission permission);
    
    // File access control
    bool canReadFile(const std::string& userId, const std::string& fileId);
    bool canWriteFile(const std::string& userId, const std::string& fileId);
    bool canDeleteFile(const std::string& userId, const std::string& fileId);
    bool isAdmin(const std::string& userId);
    
    // Role-based access control
    bool assignRole(const std::string& userId, const std::string& role);
    bool hasRole(const std::string& userId, const std::string& role);
    
private:
    // Hash password for storage
    std::string hashPassword(const std::string& password);
};

// User class
class User {
private:
    std::string userId;
    std::string username;
    std::string passwordHash;
    std::vector<std::string> roles;
    
public:
    User(const std::string& userId, const std::string& username, const std::string& passwordHash);
    
    // Getters
    std::string getUserId() const { return userId; }
    std::string getUsername() const { return username; }
    std::string getPasswordHash() const { return passwordHash; }
    std::vector<std::string> getRoles() const { return roles; }
    
    // Setters
    void setPasswordHash(const std::string& hash) { passwordHash = hash; }
    void addRole(const std::string& role) { roles.push_back(role); }
    void removeRole(const std::string& role);
    
    // Validation
    bool isValid() const;
};

#endif // ACCESS_CONTROL_H
