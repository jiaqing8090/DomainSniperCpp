#pragma once
#include <string>
#include <unordered_map>
#include <string_view>

class Dictionary {
public:
    static void Init(const std::string& filePath);
    static void InitFromMemory(const char* data, size_t size);
    static std::string Analyze(std::string_view word);
    static const std::unordered_map<std::string, std::string>& GetMap();
    static bool IsLoaded();
private:
    static std::unordered_map<std::string, std::string> dictMap;
    static bool loaded;
};
