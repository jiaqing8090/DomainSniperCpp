#include "IcpScanner.h"
#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <random>

#pragma comment(lib, "winhttp.lib")

namespace DomainSniper {

// 多个备用API端点 (接口盒子负载均衡)
static const char* API_ENDPOINTS[] = {
    "https://cn.apihz.cn/api/wangzhan/icp.php?id=88888888&key=88888888",
    "https://vip.apihz.cn/api/wangzhan/icp.php?id=88888888&key=88888888",
};
static const int API_ENDPOINT_COUNT = sizeof(API_ENDPOINTS) / sizeof(API_ENDPOINTS[0]);

IcpScanner::IcpScanner() : m_apiUrl(API_ENDPOINTS[0]) {}

IcpScanner::~IcpScanner() { stopScan(); }

void IcpScanner::setApiUrl(const std::string& url) { m_apiUrl = url; }
void IcpScanner::setApiKey(const std::string& key) { m_apiKey = key; }

void IcpScanner::stopScan() {
    m_running = false;
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void IcpScanner::startScan(const std::vector<std::string>& domains,
                            ProgressCallback onProgress,
                            FinishCallback onFinish) {
    stopScan();
    m_running = true;
    m_thread = std::thread(&IcpScanner::scanThread, this, domains, onProgress, onFinish);
}

void IcpScanner::scanThread(const std::vector<std::string>& domains,
                             ProgressCallback onProgress,
                             FinishCallback onFinish) {
    std::vector<IcpResult> results;
    int total = (int)domains.size();

    for (int i = 0; i < total && m_running; ++i) {
        const auto& domain = domains[i];
        if (domain.empty()) continue;

        IcpResult result = querySingle(domain, m_apiUrl, m_apiKey);

        if (m_running && onProgress) {
            onProgress(i + 1, total, result);
        }
        results.push_back(result);
    }

    if (m_running && onFinish) {
        onFinish(results);
    }
    m_running = false;
}

// 从URL中解析server、port、path
static bool parseUrl(const std::string& url, std::wstring& server, int& port, std::wstring& path, bool& useSSL) {
    std::string u = url;
    useSSL = false;

    if (u.substr(0, 8) == "https://") {
        useSSL = true;
        u = u.substr(8);
    } else if (u.substr(0, 7) == "http://") {
        u = u.substr(7);
    }

    // 去掉末尾斜杠
    while (!u.empty() && u.back() == '/') u.pop_back();

    size_t slashPos = u.find('/');
    std::string hostPort, uriPath;
    if (slashPos != std::string::npos) {
        hostPort = u.substr(0, slashPos);
        uriPath = u.substr(slashPos);
    } else {
        hostPort = u;
        uriPath = "/";
    }

    // 解析端口
    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        server = std::wstring(hostPort.begin(), hostPort.begin() + colonPos);
        port = std::stoi(hostPort.substr(colonPos + 1));
    } else {
        server = std::wstring(hostPort.begin(), hostPort.end());
        port = useSSL ? 443 : 80;
    }

    path = std::wstring(uriPath.begin(), uriPath.end());
    return true;
}

// 简单的JSON字符串值提取
static std::string jsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";

    // 跳过冒号和空白
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n')) pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        pos++; // 跳过开始引号
        size_t end = pos;
        while (end < json.size() && json[end] != '"') {
            if (json[end] == '\\' && end + 1 < json.size()) end++; // 跳过转义
            end++;
        }
        return json.substr(pos, end - pos);
    }

    // 数字或布尔值
    if (json[pos] == 't' || json[pos] == 'f' || json[pos] == 'n' || (json[pos] >= '0' && json[pos] <= '9')) {
        size_t end = pos;
        while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']' && json[end] != ' ' && json[end] != '\n') end++;
        return json.substr(pos, end - pos);
    }

    return "";
}

// 简单的JSON整数值提取
static int jsonGetInt(const std::string& json, const std::string& key) {
    std::string val = jsonGetString(json, key);
    if (val.empty()) return -1;
    try { return std::stoi(val); }
    catch (...) { return -1; }
}

IcpResult IcpScanner::parseResponse(const std::string& json, const std::string& domain) {
    IcpResult result;
    result.domain = domain;

    if (json.empty()) {
        result.errorMsg = "网络请求失败";
        return result;
    }

    // 解析API返回的JSON
    // 接口盒子(apihz.cn)格式:
    // 成功: {"code":200,"type":"企业","icp":"京ICP证030173号-1","unit":"北京百度网讯科技有限公司","time":"2019-05-16"}
    // 未备案: {"code":200,"type":"查询失败","icp":"查询失败","unit":"查询失败","time":"查询失败"}
    // 错误: {"code":400,"msg":"错误信息"}

    result.success = true; // HTTP请求成功，API有响应

    std::string code = jsonGetString(json, "code");
    if (code == "400") {
        std::string msg = jsonGetString(json, "msg");
        result.success = false;
        result.errorMsg = msg.empty() ? "API返回错误" : msg;
        result.hasIcp = false;
        return result;
    }

    // code == 200: 成功响应
    result.icpNumber = jsonGetString(json, "icp");
    result.companyType = jsonGetString(json, "type");
    result.companyName = jsonGetString(json, "unit");
    result.auditTime = jsonGetString(json, "time");
    result.siteUrl = jsonGetString(json, "domain");

    // 判断是否有备案: icp字段不是"查询失败"且非空
    result.hasIcp = (!result.icpNumber.empty() && result.icpNumber != "查询失败");

    if (!result.hasIcp) {
        result.errorMsg = "未备案";
    }

    return result;
}

std::string IcpScanner::httpGet(const std::wstring& server, int port,
                                 const std::wstring& path, bool useSSL,
                                 unsigned long timeoutMs) {
    std::string response;

    HINTERNET hSession = WinHttpOpen(
        L"DomainSniper/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) return "";

    // 设置全局超时
    WinHttpSetOption(hSession, WINHTTP_OPTION_RESOLVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));

    HINTERNET hConnect = WinHttpConnect(hSession, server.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }

    DWORD flags = useSSL ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // 禁用自动重定向（简化逻辑）
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    BOOL result = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (result) {
        result = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (result) {
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);

        if (dwStatusCode == 200) {
            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (dwSize == 0) break;

                char* buffer = new char[dwSize + 1];
                ZeroMemory(buffer, dwSize + 1);
                DWORD dwDownloaded = 0;
                if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                    response.append(buffer, dwDownloaded);
                }
                delete[] buffer;
            } while (dwSize > 0);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

IcpResult IcpScanner::querySingle(const std::string& domain,
                                    const std::string& apiUrl,
                                    const std::string& apiKey) {
    IcpResult result;
    result.domain = domain;

    auto start = std::chrono::steady_clock::now();

    std::string url = apiUrl.empty() ? API_ENDPOINTS[0] : apiUrl;

    // 构建完整URL: API + domain参数
    // 基础URL已包含 ?id=xxx&key=xxx，追加 &domain=
    std::string fullUrl = url;
    fullUrl += "&domain=" + domain;

    if (!apiKey.empty()) {
        fullUrl += "&key=" + apiKey;
    }

    std::wstring server, path;
    int port = 80;
    bool useSSL = false;
    if (!parseUrl(fullUrl, server, port, path, useSSL)) {
        result.errorMsg = "URL解析失败";
        return result;
    }

    // 主请求 + 重试机制
    std::string json;
    const int MAX_RETRIES = 2;
    const DWORD TIMEOUT_MS = 8000; // 8秒超时

    for (int attempt = 0; attempt <= MAX_RETRIES; ++attempt) {
        json = httpGet(server, port, path, useSSL, TIMEOUT_MS);
        if (!json.empty()) break;

        // 第一次失败后短暂等待再重试
        if (attempt < MAX_RETRIES) {
            std::this_thread::sleep_for(std::chrono::milliseconds(300 * (attempt + 1)));
        }
    }

    // 如果主URL全部失败，尝试备用API端点
    if (json.empty() && apiUrl.empty()) {
        for (int ep = 1; ep < API_ENDPOINT_COUNT; ++ep) {
            std::string backupUrl = API_ENDPOINTS[ep];
            backupUrl += "&domain=" + domain;
            if (!apiKey.empty()) backupUrl += "&key=" + apiKey;

            std::wstring backupServer, backupPath;
            int backupPort = 80;
            bool backupSSL = false;
            if (parseUrl(backupUrl, backupServer, backupPort, backupPath, backupSSL)) {
                json = httpGet(backupServer, backupPort, backupPath, backupSSL, TIMEOUT_MS);
                if (!json.empty()) break;
            }
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.responseTimeMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (json.empty()) {
        result.errorMsg = "请求超时或网络错误";
        return result;
    }

    result = parseResponse(json, domain);
    result.responseTimeMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    return result;
}

} // namespace DomainSniper
