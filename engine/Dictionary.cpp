#include "Dictionary.h"
#include <fstream>
#include <mutex>
#include <thread>
#include <iostream>
#include <vector>
std::unordered_map<std::string, std::string> Dictionary::dictMap;
bool Dictionary::loaded = false;
static std::mutex g_dictMutex;

static std::vector<std::string> ParseCSVRow(const std::string& line) {
    std::vector<std::string> row;
    bool inQuote = false;
    std::string field = "";
    for (size_t i = 0; i < line.length(); i++) {
        char c = line[i];
        if (c == '"') {
            inQuote = !inQuote;
        } else if (c == ',' && !inQuote) {
            row.push_back(field);
            field = "";
        } else {
            field += c;
        }
    }
    row.push_back(field);
    return row;
}

static std::string LimitUTF8(const std::string& str, int maxChars) {
    int chars = 0;
    size_t i = 0;
    while (i < str.length() && chars < maxChars) {
        unsigned char c = str[i];
        if ((c & 0x80) == 0) i += 1;
        else if ((c & 0xE0) == 0xC0) i += 2;
        else if ((c & 0xF0) == 0xE0) i += 3;
        else if ((c & 0xF8) == 0xF0) i += 4;
        else i += 1;
        chars++;
    }
    if (i < str.length()) return str.substr(0, i) + "...";
    return str.substr(0, i);
}

void Dictionary::Init(const std::string& filePath) {
    std::thread([filePath]() {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cerr << "Failed to open dictionary: " << filePath << std::endl;
            return;
        }

        std::unordered_map<std::string, std::string> localMap;
        std::string line;
        std::getline(file, line); // skip header

        while (std::getline(file, line)) {
            auto row = ParseCSVRow(line);
            if (row.size() < 10) continue; // need up to frq (index 9)

            std::string word = row[0];
            for (char& c : word) {
                if (c >= 'A' && c <= 'Z') c += 32;
            }

            std::string translation = row[3];
            std::string collins = row[5];
            std::string tag = row[7];
            std::string bnc_str = row[8];
            std::string frq_str = row[9];

            int bnc = 0, frq = 0;
            try { if (!bnc_str.empty()) bnc = std::stoi(bnc_str); } catch(...) {}
            try { if (!frq_str.empty()) frq = std::stoi(frq_str); } catch(...) {}

            if (bnc > 0 || frq > 0 || !tag.empty() || !collins.empty()) {
                if (!translation.empty()) {
                    // Replace newlines with " | "
                    size_t p;
                    while ((p = translation.find('\n')) != std::string::npos) translation.replace(p, 1, " | ");
                    while ((p = translation.find('\r')) != std::string::npos) translation.replace(p, 1, "");
                    // Limit length
                    localMap[word] = LimitUTF8(translation, 30);
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_dictMutex);
            dictMap = std::move(localMap);
            loaded = true;
        }
    }).detach();
}

void Dictionary::InitFromMemory(const char* data, size_t size) {
    std::thread([data, size]() {
        std::unordered_map<std::string, std::string> localMap;
        size_t pos = 0;
        auto getNextLine = [&]() -> std::string {
            if (pos >= size) return "";
            size_t start = pos;
            while (pos < size && data[pos] != '\n') pos++;
            size_t len = pos - start;
            if (len > 0 && data[pos - 1] == '\r') len--;
            if (pos < size) pos++; // skip \n
            return std::string(data + start, len);
        };

        std::string line = getNextLine(); // skip header

        while (!(line = getNextLine()).empty() || pos < size) {
            if (line.empty()) continue;
            auto row = ParseCSVRow(line);
            if (row.size() < 10) continue; // need up to frq (index 9)

            std::string word = row[0];
            for (char& c : word) {
                if (c >= 'A' && c <= 'Z') c += 32;
            }

            std::string translation = row[3];
            std::string collins = row[5];
            std::string tag = row[7];
            std::string bnc_str = row[8];
            std::string frq_str = row[9];

            int bnc = 0, frq = 0;
            try { if (!bnc_str.empty()) bnc = std::stoi(bnc_str); } catch(...) {}
            try { if (!frq_str.empty()) frq = std::stoi(frq_str); } catch(...) {}

            if (bnc > 0 || frq > 0 || !tag.empty() || !collins.empty()) {
                if (!translation.empty()) {
                    // Replace newlines with " | "
                    size_t p;
                    while ((p = translation.find('\n')) != std::string::npos) translation.replace(p, 1, " | ");
                    while ((p = translation.find('\r')) != std::string::npos) translation.replace(p, 1, "");
                    // Limit length
                    localMap[word] = LimitUTF8(translation, 30);
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_dictMutex);
            dictMap = std::move(localMap);
            loaded = true;
        }
    }).detach();
}

std::string Dictionary::Analyze(std::string_view word) {
    std::lock_guard<std::mutex> lock(g_dictMutex);
    if (!loaded) return "";
    std::string w(word);
    for (char& c : w) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    auto it = dictMap.find(w);
    if (it != dictMap.end()) {
        return it->second;
    }
    return "";
}

const std::unordered_map<std::string, std::string>& Dictionary::GetMap() {
    return dictMap;
}

bool Dictionary::IsLoaded() {
    std::lock_guard<std::mutex> lock(g_dictMutex);
    return loaded;
}
