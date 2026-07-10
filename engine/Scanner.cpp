#include "Scanner.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <mutex>
#include <iostream>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

std::atomic<bool> Scanner::isRunning{false};
std::atomic<bool> Scanner::isPaused{false};
std::atomic<int> Scanner::scannedCount{0};
std::atomic<int> Scanner::availableCount{0};
std::atomic<int> Scanner::registeredCount{0};
static std::mutex globalGenMutex;
static std::atomic<int> activeThreads{0};
static std::chrono::time_point<std::chrono::high_resolution_clock> startTime;

void Scanner::Init() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

void Scanner::Cleanup() {
    WSACleanup();
}

void Scanner::StartScan(int threads, int timeoutSec, const std::vector<std::string>& tlds, 
                      std::function<std::string()> domainGenerator,
                      int totalDomains,
                      std::function<void(const ScanResult&)> onResult,
                      std::function<void()> onFinished) {
    
    isRunning = true;
    isPaused = false;
    scannedCount = 0;
    availableCount = 0;
    registeredCount = 0;
    startTime = std::chrono::high_resolution_clock::now();
    activeThreads = threads;

    for (int i = 0; i < threads; ++i) {
        std::thread([=]() {
            while (isRunning) {
                while (isPaused && isRunning) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (!isRunning) break;

                std::string domain;
                {
                    std::lock_guard<std::mutex> lock(globalGenMutex);
                    domain = domainGenerator();
                }

                if (domain.empty()) {
                    break; // No more domains
                }

                // Parse TLD to find server
                std::string tld = domain.substr(domain.find_last_of('.') + 1);
                std::string whoisServer = "whois.verisign-grs.com";
                if (tld == "cn") whoisServer = "whois.cnnic.cn";
                else if (tld == "org") whoisServer = "whois.pir.org";
                else if (tld == "co") whoisServer = "whois.nic.co";
                else if (tld == "io") whoisServer = "whois.nic.io";

                auto startReq = std::chrono::high_resolution_clock::now();

                SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (sock != INVALID_SOCKET) {
                    // Set timeout
                    DWORD timeout = timeoutSec * 1000;
                    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
                    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

                    struct addrinfo hints = {0}, *res;
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    
                    if (getaddrinfo(whoisServer.c_str(), "43", &hints, &res) == 0) {
                        if (connect(sock, res->ai_addr, (int)res->ai_addrlen) != SOCKET_ERROR) {
                            std::string query = domain + "\r\n";
                            send(sock, query.c_str(), (int)query.length(), 0);
                            
                            char buf[4096];
                            int n = recv(sock, buf, sizeof(buf) - 1, 0);
                            if (n > 0) {
                                buf[n] = '\0';
                                std::string response(buf);
                                // Very basic check
                                bool available = false;
                                if (response.find("No match for") != std::string::npos || 
                                    response.find("not found") != std::string::npos ||
                                    response.find("No Data Found") != std::string::npos) {
                                    available = true;
                                }
                                
                                auto endReq = std::chrono::high_resolution_clock::now();
                                int ms = std::chrono::duration_cast<std::chrono::milliseconds>(endReq - startReq).count();

                                ScanResult result;
                                result.domain = domain;
                                result.tld = "." + tld;
                                result.responseTimeMs = ms;
                                result.registrar = "-";
                                result.discoveryTime = std::chrono::system_clock::now();
                                
                                if (available) {
                                    result.status = "可注册";
                                    availableCount++;
                                } else {
                                    result.status = "已注册";
                                    registeredCount++;
                                }
                                scannedCount++;
                                onResult(result);
                            }
                        }
                        freeaddrinfo(res);
                    }
                    closesocket(sock);
                }
            }
            
            if (--activeThreads == 0) {
                isRunning = false;
                onFinished();
            }
        }).detach();
    }
}

void Scanner::StopScan() {
    isRunning = false;
}

void Scanner::PauseScan() {
    isPaused = true;
}

void Scanner::ResumeScan() {
    isPaused = false;
}

int Scanner::GetScannedCount() {
    return scannedCount;
}

int Scanner::GetAvailableCount() {
    return availableCount;
}

int Scanner::GetRegisteredCount() {
    return registeredCount;
}

float Scanner::GetScansPerSecond() {
    if (scannedCount == 0) return 0.0f;
    auto now = std::chrono::high_resolution_clock::now();
    float secs = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() / 1000.0f;
    if (secs < 0.1f) return 0.0f;
    return (float)scannedCount / secs;
}

std::chrono::time_point<std::chrono::high_resolution_clock> Scanner::GetStartTime() {
    return startTime;
}
