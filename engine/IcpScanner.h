#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>

namespace DomainSniper {

struct IcpResult {
    std::string domain;           // 查询域名
    bool success = false;         // 查询是否成功
    bool hasIcp = false;          // 是否有备案
    std::string icpNumber;        // 备案号 (如: 京ICP备030173号)
    std::string companyName;      // 主办单位名称
    std::string companyType;      // 主办单位性质 (企业/个人/政府)
    std::string auditTime;        // 审核时间
    std::string siteName;         // 网站名称
    std::string siteUrl;          // 网站首页地址
    std::string errorMsg;         // 错误信息
    int responseTimeMs = 0;       // 响应时间(毫秒)
};

class IcpScanner {
public:
    using ProgressCallback = std::function<void(int current, int total, const IcpResult& result)>;
    using FinishCallback = std::function<void(const std::vector<IcpResult>& results)>;

    IcpScanner();
    ~IcpScanner();

    // 设置API地址 (默认使用免费API)
    void setApiUrl(const std::string& url);
    void setApiKey(const std::string& key);
    std::string getApiUrl() const { return m_apiUrl; }

    // 开始扫描
    void startScan(const std::vector<std::string>& domains,
                   ProgressCallback onProgress,
                   FinishCallback onFinish);

    // 停止扫描
    void stopScan();

    // 是否正在扫描
    bool isScanning() const { return m_running.load(); }

    // 单域名查询
    static IcpResult querySingle(const std::string& domain,
                                  const std::string& apiUrl = "",
                                  const std::string& apiKey = "");

private:
    void scanThread(const std::vector<std::string>& domains,
                    ProgressCallback onProgress,
                    FinishCallback onFinish);

    static std::string httpGet(const std::wstring& server, int port,
                               const std::wstring& path, bool useSSL);
    static IcpResult parseResponse(const std::string& json, const std::string& domain);

    std::string m_apiUrl;
    std::string m_apiKey;
    std::atomic<bool> m_running{false};
    std::thread m_thread;
};

} // namespace DomainSniper