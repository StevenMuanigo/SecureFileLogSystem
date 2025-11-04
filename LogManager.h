#ifndef LOG_MANAGER_H
#define LOG_MANAGER_H

#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <mutex>

// Forward declaration
class LogEntry;

class LogManager {
private:
    std::string logFilePath;
    std::mutex logMutex;
    bool enableElasticSearch;
    std::string elasticSearchUrl;
    
public:
    LogManager(const std::string& logFilePath = "secure_file_log.log");
    
    // Log file access
    void logFileAccess(const std::string& userId, const std::string& fileName, 
                      const std::string& ipAddress, const std::string& action);
    
    // Log system events
    void logSystemEvent(const std::string& event, const std::string& details = "");
    
    // Log security events
    void logSecurityEvent(const std::string& eventType, const std::string& details, 
                         const std::string& userId = "");
    
    // Get logs
    std::vector<std::shared_ptr<LogEntry>> getRecentLogs(size_t count = 100);
    
    // Enable ElasticSearch integration
    void enableElasticSearchIntegration(const std::string& url);
    
    // Send logs to ElasticSearch
    bool sendLogsToElasticSearch(const std::vector<std::shared_ptr<LogEntry>>& logs);
    
private:
    // Write log entry to file
    void writeLogEntry(const LogEntry& entry);
    
    // Format log entry as string
    std::string formatLogEntry(const LogEntry& entry);
};

// Log entry structure
class LogEntry {
public:
    std::chrono::system_clock::time_point timestamp;
    std::string userId;
    std::string fileName;
    std::string ipAddress;
    std::string action;
    std::string eventType;
    std::string details;
    
    LogEntry();
    LogEntry(const std::string& userId, const std::string& fileName, 
             const std::string& ipAddress, const std::string& action,
             const std::string& eventType = "ACCESS", const std::string& details = "");
    
    std::string toString() const;
};

#endif // LOG_MANAGER_H
