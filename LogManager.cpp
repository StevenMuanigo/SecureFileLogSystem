#include "../include/LogManager.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <iostream>
#include <curl/curl.h>

// LogEntry implementation
LogEntry::LogEntry() : timestamp(std::chrono::system_clock::now()) {}

LogEntry::LogEntry(const std::string& userId, const std::string& fileName, 
                   const std::string& ipAddress, const std::string& action,
                   const std::string& eventType, const std::string& details)
    : userId(userId), fileName(fileName), ipAddress(ipAddress), 
      action(action), eventType(eventType), details(details), 
      timestamp(std::chrono::system_clock::now()) {}

std::string LogEntry::toString() const {
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    
    return "[" + ss.str() + "] " + 
           "USER:" + userId + " " +
           "FILE:" + fileName + " " +
           "IP:" + ipAddress + " " +
           "ACTION:" + action + " " +
           "TYPE:" + eventType + " " +
           "DETAILS:" + details;
}

// LogManager implementation
LogManager::LogManager(const std::string& logFilePath) 
    : logFilePath(logFilePath), enableElasticSearch(false) {}

void LogManager::logFileAccess(const std::string& userId, const std::string& fileName, 
                              const std::string& ipAddress, const std::string& action) {
    LogEntry entry(userId, fileName, ipAddress, action, "ACCESS", "");
    writeLogEntry(entry);
    
    // Send to ElasticSearch if enabled
    if (enableElasticSearch) {
        std::vector<std::shared_ptr<LogEntry>> logs;
        logs.push_back(std::make_shared<LogEntry>(entry));
        sendLogsToElasticSearch(logs);
    }
}

void LogManager::logSystemEvent(const std::string& event, const std::string& details) {
    LogEntry entry("SYSTEM", "", "", event, "SYSTEM", details);
    writeLogEntry(entry);
}

void LogManager::logSecurityEvent(const std::string& eventType, const std::string& details, 
                                 const std::string& userId) {
    LogEntry entry(userId, "", "", "SECURITY_EVENT", eventType, details);
    writeLogEntry(entry);
    
    // Send to ElasticSearch if enabled
    if (enableElasticSearch) {
        std::vector<std::shared_ptr<LogEntry>> logs;
        logs.push_back(std::make_shared<LogEntry>(entry));
        sendLogsToElasticSearch(logs);
    }
}

std::vector<std::shared_ptr<LogEntry>> LogManager::getRecentLogs(size_t count) {
    std::vector<std::shared_ptr<LogEntry>> logs;
    // In a real implementation, this would read from the log file or database
    // For now, we'll return an empty vector
    return logs;
}

void LogManager::enableElasticSearchIntegration(const std::string& url) {
    elasticSearchUrl = url;
    enableElasticSearch = true;
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

bool LogManager::sendLogsToElasticSearch(const std::vector<std::shared_ptr<LogEntry>>& logs) {
    if (!enableElasticSearch || elasticSearchUrl.empty()) {
        return false;
    }
    
    // In a real implementation, this would send logs to ElasticSearch
    // For now, we'll just return true
    return true;
}

void LogManager::writeLogEntry(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::ofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << formatLogEntry(entry) << std::endl;
        logFile.close();
    }
}

std::string LogManager::formatLogEntry(const LogEntry& entry) {
    return entry.toString();
}
