#pragma once
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <chrono>

struct ScanResult {
    std::string domain;
    std::string tld;
    std::string status;
    int responseTimeMs;
    std::string registrar;
    std::chrono::time_point<std::chrono::system_clock> discoveryTime; // NEW: timestamp
};

class Scanner {
public:
    static void Init();
    static void Cleanup();

    // Non-blocking scan start
    static void StartScan(int threads, int timeoutSec, const std::vector<std::string>& tlds,
                          std::function<std::string()> domainGenerator,
                          int totalDomains,
                          std::function<void(const ScanResult&)> onResult,
                          std::function<void()> onFinished);

    static void StopScan();
    static void PauseScan();
    static void ResumeScan();

    static int GetScannedCount();
    static int GetAvailableCount();
    static int GetRegisteredCount();
    static float GetScansPerSecond();
    static std::chrono::time_point<std::chrono::high_resolution_clock> GetStartTime(); // NEW

private:
    static std::atomic<bool> isRunning;
    static std::atomic<bool> isPaused;
    static std::atomic<int> scannedCount;
    static std::atomic<int> availableCount;
    static std::atomic<int> registeredCount;
};
