#include "MainWindow.h"
#include "Dictionary.h"
#include "Scanner.h"
#include "IcpScanner.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include <GLFW/glfw3.h>
#include "Scanner.h"

#include <atomic>
#include <algorithm>
#include <math.h>
#include <mutex>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <sstream>
#include <ctime>
#include <chrono>
#include <cstring>
#include <cstdio>

#include "imgui.h"
#include "imgui_internal.h"

// IM_PI is only declared in imgui_internal.h; provide a public fallback.
#ifndef IM_PI
#define IM_PI 3.14159265358979323846f
#endif

#include <windows.h>
#include <commdlg.h>

#include <GLFW/glfw3.h>
#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#endif

// ===================================================================
//  Data
// ===================================================================
static std::atomic<bool> meaningAnalysisRunning{false};
static std::atomic<int> meaningAnalysisTotal{0};
static std::atomic<int> meaningAnalysisProgress{0};
static std::wstring Utf8ToWString(const std::string& utf8Str) {
    if (utf8Str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &utf8Str[0], (int)utf8Str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

struct AnalysisResult {
  std::string domain;
  std::string meaning;
  std::string pinyin;
  std::string industry;
  std::string type;
  int score;
  int seoScore;
};

static std::vector<AnalysisResult> analysisResults;
static int selectedAnalysisIdx = -1;

static std::atomic<bool> scanIsRunning{false};
static std::atomic<bool> scanIsPaused{false};
static int elapsedSeconds = 0;
static std::chrono::steady_clock::time_point lastTickTime;

static std::vector<std::string> logLines;
static std::vector<ScanResult> scanResults;
static std::mutex dataMutex;

// Scan config
static char scanDictBuf[256] = "";
static char analyzeFileBuf[256] = "";
static int threads = 500;
static int timeout = 3;
static int dnsServerIdx = 0;
static int charType = 2; // 0=纯字母 1=纯数字 2=字母+数字
static int minLen = 3;
static int maxLen = 6;
static bool extChecks[12] = {true, true, true, true, true, true,
                             true, true, true, true, true, true};
static long long currentTotalDomains = 0;
static size_t scanFileDomainIdx = 0;
static int scanCurTldIdx = 0;
static long long scanCurLen = 0;   // 内存生成模式: 当前长度
static long long scanCurIndex = 0; // 内存生成模式: 当前序号

// Analysis options
static bool anaOpt[7] = {true, true, true, true, true, true, true};

// Header active tab (cosmetic highlight)
static int activeTab = 0;

// ===================================================================
//  ICP备案查询数据
// ===================================================================
static char icpInputBuf[256 * 1024] = {0};
static char icpDictPathBuf[512] = {0};
static char icpApiUrlBuf[512] = {0};
static std::vector<DomainSniper::IcpResult> icpResults;
static std::mutex icpMutex;
static std::atomic<bool> icpScanRunning{false};
static std::atomic<int> icpScanProgress{0};
static std::atomic<int> icpScanTotal{0};
static bool icpShowHasIcp = true;
static bool icpShowNoIcp = true;
static bool icpShowError = false;
static int icpFilterMinLen = 1;
static int icpFilterMaxLen = 63;
static int icpTldIndex = 0;
static char icpTldStr[256] = "com,cn,org,net,co,io,cc,me,top,xyz,info,biz";
static DomainSniper::IcpScanner icpScanner;
static long long icpScanStartTime = 0;
static bool icpApiConfigured = false;

// 初始化ICP API URL
static void InitIcpApiUrl() {
    if (icpApiUrlBuf[0] == '\0') {
        strcpy(icpApiUrlBuf, "https://api.uomg.com/api/icp");
    }
}

// 从ICP扫描结果中导入域名到WHOIS扫描
static void ImportIcpToScan(const std::vector<DomainSniper::IcpResult>& toImport) {
    std::vector<std::string> existing;
    {
        std::lock_guard<std::mutex> lock(dataMutex);
        for (const auto& r : scanResults) {
            existing.push_back(r.domain);
        }
    }
    for (const auto& r : toImport) {
        if (std::find(existing.begin(), existing.end(), r.domain) == existing.end()) {
            importDomainQueue.push_back(r.domain);
        }
    }
    scanStartTriggered = true;
    if (!importDomainQueue.empty()) {
        strncpy(scanInputBuf, "", sizeof(scanInputBuf));
        modeIdx = 1; // switch to import mode
    }
}

// 设计稿基准：1600×900 (16:9)，所有区域尺寸按窗口等比缩放
static constexpr float kDesignRefW = 1600.0f;
static constexpr float kDesignRefH = 900.0f;

static float DesignScale() {
  const ImVec2 ds = ImGui::GetIO().DisplaySize;
  const float sx = ds.x / kDesignRefW;
  const float sy = ds.y / kDesignRefH;
  return sx < sy ? sx : sy;
}

static float DesignPx(float v) { return v * DesignScale(); }

// 全页外边距（设计稿 12px @1080p）
static const float kContentPadX = 12.0f;
static const float kContentPadY = 12.0f;
// 面板内部 padding（设计稿 10×8 @1080p）
static const ImVec2 kPanelPadding = ImVec2(10.0f, 8.0f);
static const float kColumnGap = 10.0f;
static const float kSectionGap = 8.0f;

static ImVec2 ScaledPanelPadding() {
  return ImVec2(DesignPx(kPanelPadding.x), DesignPx(kPanelPadding.y));
}

// 设计稿 Light Mode 配色
static const ImVec4 kColorTitleBarBg = ImVec4(0.145f, 0.388f, 0.922f, 1.0f);   // #2563EB
static const ImVec4 kColorBodyBg = ImVec4(0.945f, 0.961f, 0.976f, 1.0f);       // #F1F5F9
static const ImVec4 kColorPanelBg = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
static const ImVec4 kColorPanelBorder = ImVec4(0.886f, 0.910f, 0.941f, 1.0f);  // #E2E8F0
static const ImVec4 kColorTextPrimary = ImVec4(0.118f, 0.161f, 0.231f, 1.0f);  // #1E293B
static const ImVec4 kColorTextSecondary = ImVec4(0.392f, 0.451f, 0.545f, 1.0f);
static const ImVec4 kColorPrimaryBlue = ImVec4(0.231f, 0.510f, 0.965f, 1.0f);    // #3B82F6
static const ImVec4 kColorPrimaryPurple = ImVec4(0.545f, 0.361f, 0.965f, 1.0f); // #8B5CF6
static const ImVec4 kColorSuccess = ImVec4(0.063f, 0.725f, 0.506f, 1.0f);      // #10B981
static const ImVec4 kColorDanger = ImVec4(0.937f, 0.267f, 0.267f, 1.0f);        // #EF4444

static void PushPanelStyle() {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, kColorPanelBg);
  ImGui::PushStyleColor(ImGuiCol_Border, kColorPanelBorder);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ScaledPanelPadding());
}

static void PopPanelStyle() {
  ImGui::PopStyleVar();
  ImGui::PopStyleColor(2);
}

static const ImGuiWindowFlags kPanelChildFlags =
    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

static void DrawPanelShadow(ImVec2 size) {
  ImVec2 p = ImGui::GetCursorScreenPos();
  const float r = DesignPx(8.0f);
  const float off = DesignPx(2.0f);
  ImGui::GetWindowDrawList()->AddRectFilled(
      ImVec2(p.x + off, p.y + off * 1.5f), ImVec2(p.x + size.x + off, p.y + size.y + off * 1.5f),
      IM_COL32(15, 23, 42, 16), r);
}

static bool BeginPanel(const char *id, ImVec2 size, ImGuiWindowFlags flags = kPanelChildFlags) {
  DrawPanelShadow(size);
  PushPanelStyle();
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, DesignPx(8.0f));
  return ImGui::BeginChild(id, size, true, flags);
}

static void EndPanel() {
  ImGui::EndChild();
  ImGui::PopStyleVar();
  PopPanelStyle();
}
// 三行面板高度比例（相对列可用高度，取自设计稿）
static const float kScanCfgColRatio = 0.26f;
static const float kScanResColRatio = 0.37f;
static const float kAnaCfgColRatio = 0.0f; // 0 = 使用固定内容高度
static const float kAnaResColRatio = 0.38f;
// 无数据时表格/日志/详情最小高度（@1080p）
static const float kMinResTableBodyH = 200.0f;
static const float kMinAnaTableBodyH = 160.0f;
static const float kMinLogPanelH = 130.0f;
static const float kMinDetailPanelH = 128.0f;

static float GetScanCfgFixedH() {
  const float padY = DesignPx(kPanelPadding.y);
  return padY * 2.0f + ImGui::GetTextLineHeightWithSpacing() + DesignPx(8.0f) +
         ImGui::GetFrameHeightWithSpacing() * 6.0f + ImGui::GetFrameHeightWithSpacing() * 2.0f +
         DesignPx(60.0f);
}

static float GetAnaCfgFixedH() {
  const float padY = DesignPx(kPanelPadding.y);
  const float titleH = ImGui::GetTextLineHeight() + DesignPx(2.0f) + 1.0f + DesignPx(2.0f);
  return padY * 2.0f + titleH + ImGui::GetFrameHeightWithSpacing() + DesignPx(2.0f) +
         ImGui::GetTextLineHeightWithSpacing() + ImGui::GetFrameHeightWithSpacing() * 3.0f +
         DesignPx(4.0f) + DesignPx(34.0f) + DesignPx(80.0f);
}

// Window maximize state
static bool winMaximized = false;
static int restoreX = 100, restoreY = 100, restoreW = 1600, restoreH = 900;

static const char *exts[12] = {".com", ".net", ".io",  ".org", ".cn",   ".cc",
                               ".top", ".site", ".xyz", ".vip", ".online", ".info"};

static const char *dnsItems[5] = {(const char *)u8"自动 (系统默认)", "8.8.8.8 (Google)",
                                  "114.114.114.114", "1.1.1.1 (Cloudflare)",
                                  (const char *)u8"223.5.5.5 (阿里DNS)"};

// ===================================================================
//  Helpers
// ===================================================================
static std::string OpenFileDialog() {
  char szFile[MAX_PATH] = {0};
  OPENFILENAMEA ofn = {0};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = NULL;
  ofn.lpstrFile = szFile;
  ofn.nMaxFile = sizeof(szFile);
  ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
  ofn.nFilterIndex = 1;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
  if (GetOpenFileNameA(&ofn)) return szFile;
  return "";
}

static std::string SaveFileDialog(const char *filter, const char *defExt,
                                  const char *defName) {
  char szFile[MAX_PATH] = {0};
  if (defName) {
    strncpy(szFile, defName, MAX_PATH - 1);
    szFile[MAX_PATH - 1] = '\0';
  }
  OPENFILENAMEA ofn = {0};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = NULL;
  ofn.lpstrFile = szFile;
  ofn.nMaxFile = MAX_PATH;
  ofn.lpstrFilter = filter;
  ofn.nFilterIndex = 1;
  ofn.lpstrDefExt = defExt;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
  if (GetSaveFileNameA(&ofn)) return szFile;
  return "";
}

static std::string FormatNumberWithCommas(long long value) {
  std::string s = std::to_string(value);
  int insertPosition = (int)s.length() - 3;
  while (insertPosition > 0) {
    s.insert(insertPosition, ",");
    insertPosition -= 3;
  }
  return s;
}

// 表格高度：数据少时随内容收缩，避免 RowBg 在空白区画出假数据行
static float CalcTableHeight(int rowCount, float maxH) {
  const float headerH = ImGui::GetFrameHeightWithSpacing();
  const float rowH = ImGui::GetTextLineHeightWithSpacing();
  const float ideal = headerH + rowCount * rowH + ImGui::GetStyle().CellPadding.y * 2.0f;
  const float minH = headerH + rowH;
  return std::clamp(ideal, minH, maxH);
}

// 三行面板高度归一化：保证 h0+h1+h2+间距 不超过列高，优先压缩底部面板
static void FitColumnPanels(float colH, float gap, float &h0, float &h1, float &h2,
                            float min0, float min1, float min2) {
  const float gaps = gap * 2.0f;
  const float absMin = 48.0f;
  min0 = std::max(absMin, min0);
  min1 = std::max(absMin, min1);
  min2 = std::max(absMin, min2);

  h0 = std::max(min0, h0);
  h1 = std::max(min1, h1);
  h2 = std::max(min2, h2);

  auto total = [&]() { return h0 + h1 + h2 + gaps; };
  if (total() <= colH) return;

  for (int i = 0; i < 128 && total() > colH + 0.5f; i++) {
    float overflow = total() - colH;
    if (h2 > min2)
      h2 = std::max(min2, h2 - overflow);
    else if (h1 > min1)
      h1 = std::max(min1, h1 - overflow);
    else if (h0 > min0)
      h0 = std::max(min0, h0 - overflow);
    else
      break;
  }
  if (total() > colH + 0.5f)
    h2 = std::max(min2, colH - h0 - h1 - gaps);
}

static void DrawPanelTitle(const char *title, int type = 0) {
  ImFont *bigFont = ImGui::GetIO().Fonts->Fonts.Size > 2 ? ImGui::GetIO().Fonts->Fonts[2] : ImGui::GetFont();
  ImVec4 titleColor = type == 0 ? ImVec4(37.0f/255.0f, 99.0f/255.0f, 235.0f/255.0f, 1.0f) 
                                : ImVec4(139.0f/255.0f, 92.0f/255.0f, 246.0f/255.0f, 1.0f);
  ImGui::PushFont(bigFont);
  ImGui::PushStyleColor(ImGuiCol_Text, titleColor);
  ImGui::TextUnformatted(title);
  ImGui::PopStyleColor();
  ImGui::PopFont();
  ImGui::Dummy(ImVec2(0, DesignPx(4.0f)));
  ImGui::PushStyleColor(ImGuiCol_Separator, kColorPanelBorder);
  ImGui::Separator();
  ImGui::PopStyleColor();
  ImGui::Dummy(ImVec2(0, DesignPx(8.0f)));
}

static std::string GetCharset() {
  if (charType == 0) return "abcdefghijklmnopqrstuvwxyz";
  if (charType == 1) return "0123456789";
  return "abcdefghijklmnopqrstuvwxyz0123456789";
}

static std::string IndexToName(long long index, int length, const std::string &chars) {
  long long base = (long long)chars.length();
  std::string name;
  long long n = index;
  for (int i = 0; i < length; i++) {
    name = chars[n % base] + name;
    n /= base;
  }
  return name;
}

static long long ExpectedGenCount() {
  std::string chars = GetCharset();
  int N = (int)chars.length();
  if (N == 0) return 0;
  int lo = minLen, hi = maxLen;
  if (lo < 1) lo = 1;
  if (hi < lo) hi = lo;
  if (hi > 8) hi = 8;
  long long total = 0;
  for (int L = lo; L <= hi; L++) total += (long long)pow((double)N, L);
  return total;
}

static std::string FormatTimePoint(std::chrono::system_clock::time_point tp) {
  std::time_t t = std::chrono::system_clock::to_time_t(tp);
  std::tm *tmv = std::localtime(&t);
  char buf[32];
  if (tmv)
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tmv);
  else
    buf[0] = '\0';
  return buf;
}

static std::chrono::system_clock::time_point MakeTimePoint(int y, int mo, int d,
                                                           int h, int mi, int s) {
  std::tm tmv = {};
  tmv.tm_year = y - 1900;
  tmv.tm_mon = mo - 1;
  tmv.tm_mday = d;
  tmv.tm_hour = h;
  tmv.tm_min = mi;
  tmv.tm_sec = s;
  tmv.tm_isdst = -1;
  std::time_t t = std::mktime(&tmv);
  return std::chrono::system_clock::from_time_t(t);
}

static std::string GetStarsString(int score) {
  if (score >= 90) return (const char *)u8"★★★★★";
  if (score >= 80) return (const char *)u8"★★★★☆";
  if (score >= 70) return (const char *)u8"★★★☆☆";
  if (score >= 60) return (const char *)u8"★★☆☆☆";
  return (const char *)u8"★☆☆☆☆";
}

// ===================================================================
//  Meaning analysis dictionaries & logic
// ===================================================================
static const std::unordered_set<std::string> PINYIN = {
  "a","ai","an","ang","ao","ba","bai","ban","bang","bao","bei","ben","beng","bi","bian","biao","bie","bin","bing","bo","bu","ca","cai","can","cang","cao","ce","cen","ceng","cha","chai","chan","chang","chao","che","chen","cheng","chi","chong","chou","chu","chua","chuai","chuan","chuang","chui","chun","chuo","ci","cong","cou","cu","cuan","cui","cun","cuo","da","dai","dan","dang","dao","de","deng","di","dian","diao","die","ding","diu","dong","dou","du","duan","dui","dun","duo","er","fa","fan","fang","fei","fen","feng","fo","fou","fu","ga","gai","gan","gang","gao","ge","gei","gen","geng","gong","gou","gu","gua","guai","guan","guang","gui","gun","guo","ha","hai","han","hang","hao","he","hei","hen","heng","hong","hou","hu","hua","huai","huan","huang","hui","hun","huo","ji","jia","jian","jiang","jiao","jie","jin","jing","jiong","jiu","ju","juan","jue","jun","ka","kai","kan","kang","kao","ke","ken","keng","kong","kou","ku","kua","kuai","kuan","kuang","kui","kun","kuo","la","lai","lan","lang","lao","le","lei","leng","li","lia","lian","liang","liao","lie","lin","ling","liu","long","lou","lu","luan","lun","luo","lv","lve","ma","mai","man","mang","mao","me","mei","men","meng","mi","mian","miao","mie","min","ming","miu","mo","mou","mu","na","nai","nan","nang","nao","ne","nei","nen","neng","ni","nian","niang","niao","nie","nin","ning","niu","nong","nou","nu","nuan","nuo","nv","nve","ou","pa","pai","pan","pang","pao","pei","pen","peng","pi","pian","piao","pie","pin","ping","po","pou","pu","qi","qia","qian","qiang","qiao","qie","qin","qing","qiong","qiu","qu","quan","que","qun","ran","rang","rao","re","ren","reng","ri","rong","rou","ru","ruan","rui","run","ruo","sa","sai","san","sang","sao","se","sen","seng","sha","shai","shan","shang","shao","she","shen","sheng","shi","shou","shu","shua","shuai","shuan","shuang","shui","shun","shuo","si","song","sou","su","suan","sui","sun","suo","ta","tai","tan","tang","tao","te","teng","ti","tian","tiao","tie","ting","tong","tou","tu","tuan","tui","tun","tuo","wa","wai","wan","wang","wei","wen","weng","wo","wu","xi","xia","xian","xiang","xiao","xie","xin","xing","xiong","xiu","xu","xuan","xue","xun","ya","yan","yang","yao","ye","yi","yin","ying","yong","you","yu","yuan","uuid","yue","yun","za","zai","zan","zang","zao","ze","zei","zen","zeng","zha","zhai","zhan","zhang","zhao","zhe","zhen","zheng","zhi","zhong","zhou","zhu","zhua","zhuai","zhuan","zhuang","zhui","zhun","zhuo","zi","zong","zou","zu","zuan","zui","zun","zuo"
};

static const std::unordered_map<std::string, std::string> DICT_2L = {
  {"bj", "北京/保健"}, {"sh", "上海/生活"}, {"sz", "深圳/数字"}, {"gz", "广州/贵州"}, {"hz", "杭州/合作"},
  {"tj", "天津/推荐"}, {"cq", "重庆/传奇"}, {"cd", "成都/车贷"}, {"wh", "武汉/文化"}, {"xa", "西安/喜爱"},
  {"nj", "南京/农机"}, {"qd", "青岛/渠道"}, {"dl", "大连/代理"}, {"xm", "厦门/项目"}, {"fz", "福州/服装"},
  {"zz", "郑州/制造"}, {"cs", "长沙/测试"}, {"jn", "济南/聚能"}, {"cc", "长春/出差"}, {"sy", "沈阳/商业"},
  {"xj", "新疆/星级"}, {"xz", "西藏/小镇"}, {"gx", "广西/共享"}, {"nx", "宁夏/农信"}, {"hn", "河南/华南"},
  {"hb", "河北/环保"}, {"sd", "山东/时代"}, {"sx", "山西/升学"}, {"js", "江苏/建设"}, {"zj", "浙江/专家"},
  {"ah", "安徽/爱好"}, {"fj", "福建/风景"}, {"jx", "江西/机械"}, {"gd", "广东/更多"}, {"hi", "海南/嗨"},
  {"sc", "四川/市场"}, {"yn", "云南/智能"}, {"hl", "黑龙/互联"}, {"jl", "吉林/交流"}, {"ln", "辽宁/理念"},
  {"tw", "台湾/图文"}, {"am", "澳门/爱美"}, {"xg", "香港/星光"}, {"zg", "中国/资格"}, {"qq", "全球/企鹅"},
  {"qw", "全网/趣味"}, {"qg", "全国/情感"}, {"tc", "同城/套餐"}, {"xy", "校园/信用"}, {"qy", "企业/权益"},
  {"gr", "个人/工人"}, {"zn", "智能/指南"}, {"xx", "信息/学习"}, {"ds", "电商/大师"}, {"cx", "创新/诚信"},
  {"hx", "和谐/核心"}, {"fy", "飞跃/翻译"}, {"cy", "产业/餐饮"}, {"zy", "资源/卓越"},
  {"rz", "融资/入驻"}, {"ch", "策划/吃喝"}, {"yx", "游戏/营销"}, {"tg", "推广/团购"},
  {"gq", "供求/高清"}, {"zh", "综合/智慧"}, {"jy", "教育/交易"}, {"pt", "平台/普通"}, {"dt", "大厅/动态"},
  {"wq", "网圈/维权"}, {"sq", "社区/申请"}, {"bl", "部落/便利"}, {"kj", "科技/空间"}, {"qz", "圈子/求职"},
  {"zx", "中心/咨询/在线"}, {"wl", "网络/物流"}, {"tz", "投资/特价"}, {"sm", "商贸/数码"}, {"qc", "汽车/器材"},
  {"fc", "房产/风采"}, {"yl", "医疗/娱乐"}, {"jr", "金融/假日"}, {"ly", "旅游/留言"}, {"yh", "银行/用户"},
  {"bx", "保险/报销"}, {"zq", "证券/赚钱"}, {"jj", "基金/姐姐/家居"}, {"xw", "新闻/希望"}, {"mt", "媒体/模特"},
  {"gg", "广告/哥哥/公告"}, {"sj", "数据/设计/手机"}, {"jz", "建筑/兼职"}, {"gc", "工程/广场"}, {"hg", "化工/火锅"},
  {"ny", "农业/能源"}, {"dz", "电子/定制"}, {"tx", "通信/腾讯"}, {"rj", "软件/日记"}, {"dm", "动漫/代码"},
  {"ys", "影视/艺术"}, {"yy", "医院/音乐/语音"}, {"fw", "服务/房屋"}, {"gl", "管理/攻略"}, {"px", "培训/批发"},
  {"hr", "人才/华人"}, {"zp", "招聘/正品"}, {"lt", "论坛/聊天"}, {"bk", "博客/爆款"}, {"dh", "导航/电话"},
  {"ss", "搜索/赛事/叔叔"}, {"gw", "购物/官网"}, {"wm", "外卖/网民"}, {"kd", "快递/宽带"}, {"sw", "商务/税务"},
  {"ls", "律师/零售"}, {"cw", "财务/宠物"}, {"jt", "集团/交通"}, {"gf", "股份/官方"}, {"my", "贸易/母婴"},
  {"cp", "产品/彩票"}, {"bg", "办公/报告"}, {"sn", "室内/少女"}, {"hw", "户外/海外"}, {"dq", "电器/地区"},
  {"jc", "建材/教程"}, {"wy", "物业/网易"}, {"sp", "食品/视频"}, {"cl", "材料/车辆"}, {"zb", "直播/周边"},
  {"hs", "婚纱/回收"}, {"mr", "美容/名人"}, {"mz", "美妆/民族"}, {"fs", "服饰/粉丝"}, {"xb", "鞋包/学霸"},
  {"wj", "玩具/五金"}, {"ty", "体育/体验"}, {"yj", "眼镜/硬件"}, {"bd", "百度/本地"}, {"jd", "京东/酒店"},
  {"tb", "淘宝/贴吧"}, {"wx", "微信/维修"}, {"ai", "AI/爱"}, {"vr", "VR/威客"}, {"mm", "妹妹/密码"},
  {"dd", "弟弟/滴滴"}, {"bb", "宝宝/爸爸"}
};

static const std::unordered_map<std::string, std::string> DICT_1L = {
  {"w", "网"}, {"c", "城"}, {"t", "通"}, {"b", "宝"}, {"q", "圈"}, {"y", "云"},
  {"d", "店"}, {"s", "搜"}, {"k", "客"}, {"p", "派"}, {"h", "汇"}, {"j", "家"},
  {"z", "站"}, {"g", "购"}, {"m", "猫"}, {"f", "坊"}, {"x", "秀"}, {"l", "链"}
};

static const std::unordered_map<std::string, std::string> PINYIN_DICT = {
  {"ba", "吧"}, {"bo", "博/播"}, {"ge", "哥"}, {"ji", "机/鸡"}, {"ka", "卡"},
  {"ke", "客/课"}, {"ku", "库/酷"}, {"ma", "码/马"}, {"mi", "米/秘"}, {"pu", "铺"},
  {"qu", "区/趣"}, {"tu", "图/途"}, {"ya", "鸭/雅"}, {"ye", "业/页"}, {"yi", "医/易"},
  {"yu", "鱼/娱"}, {"zu", "租/族"}
};

static const std::unordered_map<std::string, std::string> POPULAR_ACRONYMS = {
  {"yyds", "永远滴神"}, {"awsl", "啊我死了"}, {"xswl", "笑死我了"}, {"nsdd", "你说得对"},
  {"vip", "VIP贵宾"}, {"ceo", "首席执行官"}, {"cfo", "首席财务官"}, {"cto", "技术总监"},
  {"app", "APP应用"}, {"atm", "取款机"}, {"kfc", "肯德基"}, {"ufo", "UFO"},
  {"bbs", "论坛"}, {"diy", "自己动手"}, {"o2o", "O2O"}, {"b2b", "B2B"}, {"b2c", "B2C"},
  {"api", "API接口"}, {"sdk", "SDK"}, {"usb", "USB"},
  {"cpu", "CPU"}, {"gpu", "GPU"}, {"ram", "内存"}, {"rom", "ROM"}, {"gps", "GPS"},
  {"pos", "POS机"}, {"erp", "ERP系统"}, {"crm", "CRM系统"}, {"oa", "OA系统"},
  {"ktv", "KTV"}, {"acg", "动漫游戏"}, {"lol", "英雄联盟"}
};

static bool CheckPinyinRecursive(const std::string &word, size_t start,
                                 std::vector<std::string> &parts) {
  if (start == word.length()) return true;
  if (parts.size() > 16) return false;
  for (size_t end = start + 1; end <= word.length() && end - start <= 6; ++end) {
    std::string sub = word.substr(start, end - start);
    if (PINYIN.count(sub)) {
      parts.push_back(sub);
      if (CheckPinyinRecursive(word, end, parts)) return true;
      parts.pop_back();
    }
  }
  return false;
}

static std::vector<std::string> CheckPinyin(const std::string &word) {
  std::vector<std::string> parts;
  if (CheckPinyinRecursive(word, 0, parts)) return parts;
  return {};
}

static std::string CheckPattern(const std::string &str) {
  if (str.length() == 4) {
    if (str[0] == str[1] && str[2] == str[3]) return (const char *)u8"AABB型";
    if (str[0] == str[2] && str[1] == str[3]) return (const char *)u8"ABAB型";
    if (str[0] == str[3] && str[1] == str[2]) return (const char *)u8"ABBA型";
    if (str[0] == str[1] && str[1] == str[2]) return (const char *)u8"AAAB型";
    if (str[1] == str[2] && str[2] == str[3]) return (const char *)u8"ABBB型";
    if (str[1] - str[0] == 1 && str[2] - str[1] == 1 && str[3] - str[2] == 1)
      return (const char *)u8"ABCD顺子";
  } else if (str.length() == 3) {
    if (str[0] == str[1] && str[1] == str[2]) return (const char *)u8"AAA豹子";
    if (str[0] == str[2]) return (const char *)u8"ABA型";
    if (str[1] - str[0] == 1 && str[2] - str[1] == 1) return (const char *)u8"ABC顺子";
  }
  return "";
}

static std::string CombineMeanings(const std::string &str1, const std::string &str2) {
  std::vector<std::string> parts1, parts2;
  std::stringstream ss1(str1), ss2(str2);
  std::string item;
  while (std::getline(ss1, item, '/')) parts1.push_back(item);
  while (std::getline(ss2, item, '/')) parts2.push_back(item);
  std::string result = "";
  for (size_t i = 0; i < parts1.size(); ++i) {
    for (size_t j = 0; j < parts2.size(); ++j) {
      if (!result.empty()) result += " / ";
      result += parts1[i] + parts2[j];
    }
  }
  return result;
}

static std::string CheckAcronym(const std::string &str) {
  auto it = POPULAR_ACRONYMS.find(str);
  if (it != POPULAR_ACRONYMS.end()) return it->second;

  if (str.length() == 4) {
    std::string p1 = str.substr(0, 2);
    std::string p2 = str.substr(2, 2);
    auto it1 = DICT_2L.find(p1);
    auto it2 = DICT_2L.find(p2);
    std::vector<std::string> py1 = CheckPinyin(p1);
    std::vector<std::string> py2 = CheckPinyin(p2);
    bool isPy1 = (py1.size() == 1);
    bool isPy2 = (py2.size() == 1);
    if (it1 != DICT_2L.end() && it2 != DICT_2L.end())
      return CombineMeanings(it1->second, it2->second);
    auto itp2 = PINYIN_DICT.find(p2);
    if (it1 != DICT_2L.end() && isPy2 && itp2 != PINYIN_DICT.end())
      return CombineMeanings(it1->second, itp2->second);
    auto itp1 = PINYIN_DICT.find(p1);
    if (isPy1 && itp1 != PINYIN_DICT.end() && it2 != DICT_2L.end())
      return CombineMeanings(itp1->second, it2->second);
  } else if (str.length() == 3) {
    std::string p1 = str.substr(0, 2);
    std::string p2 = str.substr(2, 1);
    auto it1 = DICT_2L.find(p1);
    auto it2 = DICT_1L.find(p2);
    if (it1 != DICT_2L.end() && it2 != DICT_1L.end())
      return CombineMeanings(it1->second, it2->second);
  }
  return "";
}

// ===================================================================
//  Analysis
// ===================================================================
static void AnalyzeDomains(const char *fileBuf) {
  if (meaningAnalysisRunning) return;
  if (!fileBuf) return;

  std::vector<std::string> domainsToAnalyze;
  std::string inputBaseName = "scanned_results";

  if (strlen(fileBuf) > 0) {
    std::ifstream infile(fileBuf);
    if (infile.is_open()) {
      std::string line;
      while (std::getline(infile, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
          line.pop_back();
        if (!line.empty()) domainsToAnalyze.push_back(line);
      }
      infile.close();
      std::string pathStr(fileBuf);
      size_t lastSlash = pathStr.find_last_of("\\/");
      std::string fileName =
          (lastSlash == std::string::npos) ? pathStr : pathStr.substr(lastSlash + 1);
      size_t dot = fileName.find_last_of('.');
      inputBaseName = (dot != std::string::npos) ? fileName.substr(0, dot) : fileName;
    } else {
      std::lock_guard<std::mutex> lock(dataMutex);
      logLines.push_back((const char *)u8"[FAIL] 无法打开导入的文件，改用扫描结果: " +
                         std::string(fileBuf));
    }
  }

  if (domainsToAnalyze.empty()) {
    std::lock_guard<std::mutex> lock(dataMutex);
    for (const auto &r : scanResults)
      if (r.status == (const char *)u8"可注册") domainsToAnalyze.push_back(r.domain);
  }

  if (domainsToAnalyze.empty()) {
    {
      std::lock_guard<std::mutex> lock(dataMutex);
      logLines.push_back((const char *)u8"[FAIL] 没有可供分析的域名，请先扫描或导入文件");
    }
    return;
  }

  std::string inputBaseNameStr = inputBaseName;
  std::vector<std::string> domainsCopy = domainsToAnalyze;
  meaningAnalysisTotal = (int)domainsCopy.size();
  meaningAnalysisProgress = 0;
  meaningAnalysisRunning = true;

  std::thread([domainsCopy, inputBaseNameStr]() {
    CreateDirectoryA("results_meaning", NULL);
    std::ofstream outWord(Utf8ToWString("results_meaning/" + inputBaseNameStr + "_英文单词.txt").c_str());
    std::ofstream outAcronym(Utf8ToWString("results_meaning/" + inputBaseNameStr + "_极品词组.txt").c_str());
    std::ofstream outPinyin(Utf8ToWString("results_meaning/" + inputBaseNameStr + "_纯双拼.txt").c_str());
    std::ofstream outPattern(Utf8ToWString("results_meaning/" + inputBaseNameStr + "_特殊规律.txt").c_str());
    std::ofstream outNumber(Utf8ToWString("results_meaning/" + inputBaseNameStr + "_纯数字.txt").c_str());
    std::ofstream outNone(Utf8ToWString("results_meaning/" + inputBaseNameStr + "_无寓意.txt").c_str());

    std::vector<AnalysisResult> newResults;
    newResults.reserve(domainsCopy.size());

    for (const auto &dom : domainsCopy) {
    std::string prefix = dom;
    size_t dot = dom.find_first_of('.');
    if (dot != std::string::npos) prefix = dom.substr(0, dot);

    std::string lowerPrefix = prefix;
    for (char &c : lowerPrefix)
      if (c >= 'A' && c <= 'Z') c += 32;

    AnalysisResult res;
    res.domain = dom;
    res.meaning = "";
    res.pinyin = "-";
    res.industry = (const char *)u8"通用";
    res.type = "";
    res.score = 60;

    bool isNumber = true;
    for (char c : lowerPrefix)
      if (c < '0' || c > '9') { isNumber = false; break; }

    if (isNumber) {
      res.type = (const char *)u8"纯数字";
      res.meaning = (const char *)u8"纯数字域名";
      res.score = (lowerPrefix.length() <= 4) ? 88 : 70;
      std::string pat = CheckPattern(lowerPrefix);
      if (!pat.empty()) { res.meaning += " (" + pat + ")"; res.score += 8; }
      outNumber << dom << " ---- [纯数字]\n";
    } else if (lowerPrefix.length() >= 3 && !Dictionary::Analyze(lowerPrefix).empty()) {
      std::string trans = Dictionary::Analyze(lowerPrefix);
      size_t p;
      while ((p = trans.find('\n')) != std::string::npos) trans.replace(p, 1, " | ");
      while ((p = trans.find('\r')) != std::string::npos) trans.replace(p, 1, "");
      res.type = (const char *)u8"英文单词";
      res.meaning = (const char *)u8"英文单词: " + trans;
      res.industry = (const char *)u8"科技 / 互联网 / 商业";
      res.score = (lowerPrefix.length() <= 5) ? 90 : 75;
      if (lowerPrefix.find("ai") != std::string::npos ||
          lowerPrefix.find("tech") != std::string::npos) {
        res.score += 5;
        res.industry = (const char *)u8"科技 / AI";
      }
      outWord << dom << " ---- [单词: " << lowerPrefix << " (" << trans << ")]\n";
    } else if (!CheckAcronym(lowerPrefix).empty()) {
      std::string acronymMeaning = CheckAcronym(lowerPrefix);
      res.type = (const char *)u8"极品词组";
      res.meaning = (const char *)u8"极品词组: " + acronymMeaning;
      res.industry = (const char *)u8"企业 / 品牌 / 商业建站";
      res.score = (lowerPrefix.length() <= 3) ? 86 : 78;
      if (lowerPrefix.length() == 4) res.industry = (const char *)u8"区域 / 行业专称";
      outAcronym << dom << " ---- [极品词组: " << acronymMeaning << "]\n";
    } else if (!CheckPinyin(lowerPrefix).empty() && CheckPinyin(lowerPrefix).size() <= 2) {
      std::vector<std::string> pinyinParts = CheckPinyin(lowerPrefix);
      std::string pyStr = "";
      for (size_t k = 0; k < pinyinParts.size(); k++) {
        pyStr += pinyinParts[k];
        if (k < pinyinParts.size() - 1) pyStr += " ";
      }
      res.type = (const char *)u8"纯双拼";
      res.pinyin = pyStr;
      res.meaning = (const char *)u8"纯双拼结构 (" + pyStr + ")";
      res.industry = (const char *)u8"通用拼音建站";
      res.score = 80;
      outPinyin << dom << " ---- [拼音: " << pyStr << "]\n";
    } else if (!CheckPattern(lowerPrefix).empty()) {
      std::string pat = CheckPattern(lowerPrefix);
      res.type = (const char *)u8"特殊规律";
      res.meaning = (const char *)u8"特殊规律: " + pat;
      res.score = 75;
      outPattern << dom << " ---- [规律: " << pat << "]\n";
    } else {
      res.type = (const char *)u8"无寓意";
      res.meaning = (const char *)u8"无明显寓意/乱码组合";
      res.score = 52;
      outNone << dom << "\n";
    }

    if (res.score > 99) res.score = 99;
    if (res.score < 50) res.score = 50;
    res.seoScore = res.score - (rand() % 5);
    if (res.seoScore > 99) res.seoScore = 99;
    if (res.seoScore < 50) res.seoScore = 50;
    newResults.push_back(res);
    meaningAnalysisProgress++;
  }

  {
    std::lock_guard<std::mutex> lock(dataMutex);
    analysisResults = std::move(newResults);
    selectedAnalysisIdx = analysisResults.empty() ? -1 : 0;
    logLines.push_back((const char *)u8"[OK] 已完成 " +
                       std::to_string(analysisResults.size()) +
                       (const char *)u8" 个域名的匹配分析");
    logLines.push_back((const char *)u8"[INFO] 分类文件已写入 results_meaning/ 目录");
  }
  meaningAnalysisRunning = false;
  }).detach();
}

// ===================================================================
//  Export
// ===================================================================
static void ExportResults(int fmt) { // 0 = txt, 1 = csv, 2 = xls
  std::vector<ScanResult> snapshot;
  {
    std::lock_guard<std::mutex> lock(dataMutex);
    snapshot = scanResults;
  }
  if (snapshot.empty()) {
    std::lock_guard<std::mutex> lock(dataMutex);
    logLines.push_back((const char *)u8"[FAIL] 没有可导出的扫描结果");
    return;
  }

  std::string path;
  if (fmt == 0)
    path = SaveFileDialog("Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0", "txt",
                          "scan_results.txt");
  else if (fmt == 1)
    path = SaveFileDialog("CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0", "csv",
                          "scan_results.csv");
  else
    path = SaveFileDialog("Excel Files (*.xls)\0*.xls\0All Files (*.*)\0*.*\0", "xls",
                          "scan_results.xls");
  if (path.empty()) return;

  std::ofstream out(path, std::ios::binary);
  if (!out.is_open()) {
    std::lock_guard<std::mutex> lock(dataMutex);
    logLines.push_back((const char *)u8"[FAIL] 导出失败: 无法写入文件");
    return;
  }

  if (fmt == 0) {
    for (const auto &r : snapshot) out << r.domain << "\r\n";
  } else if (fmt == 1) {
    out << "\xEF\xBB\xBF"; // UTF-8 BOM so Excel shows Chinese
    out << (const char *)u8"域名,后缀,状态,响应时间(ms),注册商,发现时间\r\n";
    for (const auto &r : snapshot)
      out << r.domain << "," << r.tld << "," << r.status << "," << r.responseTimeMs
          << "," << r.registrar << "," << FormatTimePoint(r.discoveryTime) << "\r\n";
  } else {
    out << "\xEF\xBB\xBF";
    out << "<html><head><meta charset=\"utf-8\"></head><body>";
    out << "<table border=\"1\" cellspacing=\"0\">";
    out << (const char *)u8"<tr><th>域名</th><th>后缀</th><th>状态</th>"
                          u8"<th>响应时间(ms)</th><th>注册商</th><th>发现时间</th></tr>";
    for (const auto &r : snapshot)
      out << "<tr><td>" << r.domain << "</td><td>" << r.tld << "</td><td>" << r.status
          << "</td><td>" << r.responseTimeMs << "</td><td>" << r.registrar
          << "</td><td>" << FormatTimePoint(r.discoveryTime) << "</td></tr>";
    out << "</table></body></html>";
  }
  out.close();
  std::lock_guard<std::mutex> lock(dataMutex);
  logLines.push_back((const char *)u8"[OK] 已导出 " +
                     std::to_string(snapshot.size()) + (const char *)u8" 条结果 -> " + path);
}

static void ClearResults() {
  std::lock_guard<std::mutex> lock(dataMutex);
  scanResults.clear();
  logLines.clear();
  logLines.push_back((const char *)u8"[INFO] 已清空扫描结果");
}

// ===================================================================
//  Scan control
// ===================================================================
static void StartScanAction() {
  Scanner::Init();
  {
    std::lock_guard<std::mutex> lock(dataMutex);
    scanResults.clear();
    logLines.clear();
    logLines.push_back((const char *)u8"[INFO] 初始化扫描器...");
  }

  std::vector<std::string> tlds;
  for (int i = 0; i < 12; i++)
    if (extChecks[i]) tlds.push_back(std::string(exts[i]).substr(1));
  if (tlds.empty()) tlds.push_back("com");

  std::vector<std::string> loadedDomains;
  if (strlen(scanDictBuf) > 0) {
    std::ifstream infile(scanDictBuf);
    if (infile.is_open()) {
      std::string line;
      while (std::getline(infile, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
          line.pop_back();
        if (!line.empty()) loadedDomains.push_back(line);
      }
      infile.close();
    }
  }

  if (threads <= 0) {
    std::lock_guard<std::mutex> lock(dataMutex);
    logLines.push_back((const char *)u8"[Error] 扫描线程数必须大于 0");
    return;
  }
  if (timeout <= 0) {
    std::lock_guard<std::mutex> lock(dataMutex);
    logLines.push_back((const char *)u8"[Error] 超时时间必须大于 0");
    return;
  }

  // 字典文件可读 -> 字典模式; 否则按 字符类型 + 字符长度 内存生成
  bool memMode = loadedDomains.empty();
  long long totalToScan = 0;
  scanFileDomainIdx = 0;
  scanCurTldIdx = 0;
  scanCurIndex = 0;

  if (memMode) {
    if (minLen < 1) minLen = 1;
    if (maxLen < minLen) maxLen = minLen;
    if (maxLen > 8) maxLen = 8;
    scanCurLen = minLen;
    long long gen = ExpectedGenCount();
    if (gen <= 0) {
      std::lock_guard<std::mutex> lock(dataMutex);
      logLines.push_back((const char *)u8"[Error] 预计生成数量为 0，请检查字符类型与长度");
      return;
    }
    totalToScan = gen * (long long)tlds.size();
  } else {
    totalToScan = (long long)loadedDomains.size() * (long long)tlds.size();
  }

  currentTotalDomains = totalToScan;
  scanIsRunning = true;
  scanIsPaused = false;
  elapsedSeconds = 0;
  lastTickTime = std::chrono::steady_clock::now();
  {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (memMode)
      logLines.push_back((const char *)u8"[INFO] 开始扫描(内存生成)，预计 " +
                         FormatNumberWithCommas(totalToScan) +
                         (const char *)u8" 个域名");
    else
      logLines.push_back((const char *)u8"[INFO] 开始扫描，字典: " +
                         std::to_string(loadedDomains.size()) +
                         (const char *)u8" 条 x " + std::to_string(tlds.size()) +
                         (const char *)u8" 后缀");
  }

  auto generator = [loadedDomains, tlds, memMode]() -> std::string {
    if (memMode) {
      std::string chars = GetCharset();
      int hi = maxLen;
      if (hi > 8) hi = 8;
      while (scanCurLen <= (long long)hi) {
        long long total = (long long)pow((double)chars.length(), (double)scanCurLen);
        if (scanCurIndex < total) {
          std::string dom = IndexToName(scanCurIndex, (int)scanCurLen, chars);
          std::string full = dom + "." + tlds[scanCurTldIdx];
          scanCurTldIdx++;
          if (scanCurTldIdx >= (int)tlds.size()) {
            scanCurTldIdx = 0;
            scanCurIndex++;
          }
          return full;
        } else {
          scanCurIndex = 0;
          scanCurLen++;
        }
      }
      return "";
    }
    if (scanFileDomainIdx < loadedDomains.size()) {
      std::string full = loadedDomains[scanFileDomainIdx] + "." + tlds[scanCurTldIdx];
      scanCurTldIdx++;
      if (scanCurTldIdx >= (int)tlds.size()) {
        scanCurTldIdx = 0;
        scanFileDomainIdx++;
      }
      return full;
    }
    return "";
  };

  Scanner::StartScan(
      threads, timeout, tlds, generator, (int)totalToScan,
      [](const ScanResult &r) {
        std::lock_guard<std::mutex> lock(dataMutex);
        if (r.status == (const char *)u8"可注册") {
          scanResults.push_back(r);
          if (scanResults.size() > 1000) scanResults.erase(scanResults.begin());
          logLines.push_back((const char *)u8"[OK] " + r.domain +
                             (const char *)u8" 可注册 " +
                             std::to_string(r.responseTimeMs) + "ms");
          if (logLines.size() > 200) logLines.erase(logLines.begin());
        }
      },
      []() {
        std::lock_guard<std::mutex> lock(dataMutex);
        logLines.push_back((const char *)u8"[INFO] 扫描任务已完成。");
        scanIsRunning = false;
      });
}

// ===================================================================
//  自定义标题栏（无边框窗口的拖拽区 + 最小化/最大化/关闭）
// ===================================================================
static void ToggleMaximize(GLFWwindow *window) {
  if (!winMaximized) {
    glfwGetWindowPos(window, &restoreX, &restoreY);
    glfwGetWindowSize(window, &restoreW, &restoreH);
    GLFWmonitor *mon = glfwGetPrimaryMonitor();
    if (mon) {
      int mx, my, mw, mh;
      glfwGetMonitorWorkarea(mon, &mx, &my, &mw, &mh);
      glfwSetWindowPos(window, mx, my);
      glfwSetWindowSize(window, mw, mh);
      winMaximized = true;
    }
  } else {
    glfwSetWindowPos(window, restoreX, restoreY);
    glfwSetWindowSize(window, restoreW, restoreH);
    winMaximized = false;
  }
}

static void WindowButton(ImDrawList *dl, GLFWwindow *window, const char *id,
                         ImVec2 pos, ImVec2 size, int type) {
  ImGui::SetCursorPos(pos);
  ImGui::InvisibleButton(id, size);
  bool hov = ImGui::IsItemHovered();
  ImVec2 rmin = ImGui::GetItemRectMin();
  ImVec2 rmax = ImGui::GetItemRectMax();
  if (hov) {
    ImU32 hc = (type == 2) ? IM_COL32(232, 17, 35, 255) : IM_COL32(255, 255, 255, 38);
    dl->AddRectFilled(rmin, rmax, hc);
  }
  ImU32 ic = IM_COL32(220, 225, 235, 255);
  ImVec2 c = ImVec2((rmin.x + rmax.x) * 0.5f, (rmin.y + rmax.y) * 0.5f);
  float s = 5.0f;
  if (type == 0) {
    dl->AddLine(ImVec2(c.x - s, c.y), ImVec2(c.x + s, c.y), ic, 1.5f);
  } else if (type == 1) {
    if (winMaximized) {
      dl->AddRect(ImVec2(c.x - s + 2, c.y - s), ImVec2(c.x + s, c.y + s - 2), ic, 0, 0, 1.3f);
      dl->AddRectFilled(ImVec2(c.x - s, c.y - s + 2), ImVec2(c.x - s + 1.5f, c.y + s), ic);
      dl->AddRect(ImVec2(c.x - s, c.y - s + 2), ImVec2(c.x + s - 2, c.y + s), ic, 0, 0, 1.3f);
    } else {
      dl->AddRect(ImVec2(c.x - s, c.y - s), ImVec2(c.x + s, c.y + s), ic, 0, 0, 1.3f);
    }
  } else {
    dl->AddLine(ImVec2(c.x - s, c.y - s), ImVec2(c.x + s, c.y + s), ic, 1.5f);
    dl->AddLine(ImVec2(c.x - s, c.y + s), ImVec2(c.x + s, c.y - s), ic, 1.5f);
  }
  if (ImGui::IsItemClicked()) {
    if (type == 0) glfwIconifyWindow(window);
    else if (type == 1) ToggleMaximize(window);
    else glfwSetWindowShouldClose(window, true);
  }
}

static void DrawTitleBar(GLFWwindow *window, float height) {
  HWND hwnd = glfwGetWin32Window(window);
  ImGui::PushStyleColor(ImGuiCol_ChildBg, kColorTitleBarBg);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
  ImGui::BeginChild("TitleBar", ImVec2(0, height), false, ImGuiWindowFlags_NoScrollbar);

  ImDrawList *dl = ImGui::GetWindowDrawList();
  ImVec2 winPos = ImGui::GetWindowPos();
  float w = ImGui::GetWindowWidth();

  // 全宽拖拽热区（置于最底层）；后续按钮用 AllowOverlap 叠在上面仍可点击
  ImGui::SetCursorPos(ImVec2(0, 0));
  ImGui::SetNextItemAllowOverlap();
  ImGui::InvisibleButton("##titledrag", ImVec2(w, height));
  if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
    ImGui::ClearActiveID();
    ReleaseCapture();
    SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
  }
  if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
    ToggleMaximize(window);

  // Logo 圆点 + 应用标题：左边缘与 kContentPadX 对齐，与下方卡片/分栏垂直对齐
  float cy = height * 0.5f;

  static GLuint iconTex = 0;
  static bool iconLoaded = false;
  static int iconW = 0, iconH = 0;
  if (!iconLoaded) {
      int channels;
      unsigned char* data = nullptr;
      HRSRC hResImg = FindResourceA(NULL, MAKEINTRESOURCEA(103), (LPCSTR)RT_RCDATA);
      if (hResImg) {
          HGLOBAL hData = LoadResource(NULL, hResImg);
          DWORD size = SizeofResource(NULL, hResImg);
          const void* pData = LockResource(hData);
          if (pData) {
              data = stbi_load_from_memory((const stbi_uc*)pData, size, &iconW, &iconH, &channels, 4);
          }
      }
      if (data) {
          glGenTextures(1, &iconTex);
          glBindTexture(GL_TEXTURE_2D, iconTex);
          glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
          glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
          glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, iconW, iconH, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
          stbi_image_free(data);
      }
      iconLoaded = true;
  }

  if (iconTex) {
      ImGui::SetCursorPos(ImVec2(DesignPx(kContentPadX), cy - DesignPx(10.0f)));
      ImGui::Image((ImTextureID)(intptr_t)iconTex, ImVec2(DesignPx(20.0f), DesignPx(20.0f)));
  } else {
      dl->AddCircleFilled(ImVec2(winPos.x + DesignPx(kContentPadX) + DesignPx(7.0f), winPos.y + cy),
                          DesignPx(7.0f), IM_COL32(45, 120, 210, 255));
      dl->AddCircle(ImVec2(winPos.x + DesignPx(kContentPadX) + DesignPx(7.0f), winPos.y + cy),
                    DesignPx(7.0f), IM_COL32(120, 180, 255, 255), 24, 1.2f);
  }

  ImGui::SetCursorPos(
      ImVec2(DesignPx(kContentPadX) + DesignPx(28.0f), (height - ImGui::GetTextLineHeight()) * 0.5f));
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
  ImGui::TextUnformatted((const char *)u8"未注册域名扫描工具 v1.0.0");
  ImGui::PopStyleColor();

  // 右侧：窗口控制按钮（关闭/最大化/最小化）+ 帮助/设置
  float ctrlW = 46.0f;
  float x = w;
  x -= ctrlW; WindowButton(dl, window, "##close", ImVec2(x, 0), ImVec2(ctrlW, height), 2);
  x -= ctrlW; WindowButton(dl, window, "##max", ImVec2(x, 0), ImVec2(ctrlW, height), 1);
  x -= ctrlW; WindowButton(dl, window, "##min", ImVec2(x, 0), ImVec2(ctrlW, height), 0);

  x -= 60.0f;
  ImGui::SetCursorPos(ImVec2(x, (height - 24.0f) * 0.5f));
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 1, 1, 0.2f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 1, 1, 0.3f));
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 0.8f));
  if (ImGui::Button((const char *)u8"关于", ImVec2(50, 24))) {
      ImGui::OpenPopup((const char *)u8"关于");
  }
  ImGui::PopStyleColor(4);

  ImGui::SetNextWindowPos(ImVec2(w * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
  
  ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_TitleBg, kColorPrimaryBlue);
  ImGui::PushStyleColor(ImGuiCol_TitleBgActive, kColorPrimaryBlue);
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.15f, 0.15f, 0.15f, 1.0f));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24.0f, 20.0f));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 8.0f));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);

  if (ImGui::BeginPopupModal((const char *)u8"关于", NULL, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
      ImGui::TextColored(kColorPrimaryBlue, (const char *)u8"未注册域名扫描工具");
      ImGui::Separator();
      ImGui::Dummy(ImVec2(0, 4));
      ImGui::TextUnformatted((const char *)u8"版本：v1.0.0");
      ImGui::TextUnformatted((const char *)u8"开发：云程开源开发");
      ImGui::TextUnformatted((const char *)u8"授权：免费使用");
      ImGui::Dummy(ImVec2(0, 16));
      
      ImGui::PushStyleColor(ImGuiCol_Button, kColorPrimaryBlue);
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.5f, 0.9f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.1f, 0.4f, 0.8f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
      if (ImGui::Button((const char *)u8"确 定", ImVec2(180, 36))) {
          ImGui::CloseCurrentPopup();
      }
      ImGui::PopStyleColor(4);
      ImGui::EndPopup();
  }

  ImGui::PopStyleVar(4);
  ImGui::PopStyleColor(4);

  ImGui::EndChild();
  ImGui::PopStyleVar(3);
  ImGui::PopStyleColor();
}

// ===================================================================
//  顶栏功能卡片（左：域名扫描 / 右：域名寓意分析，与下方 62%/38% 分栏对齐）
// ===================================================================
static void DrawCardIcon(ImDrawList *dl, ImVec2 center, int type, float r) {
  dl->AddCircleFilled(center, r, IM_COL32(255, 255, 255, 45));
  dl->AddCircle(center, r, IM_COL32(255, 255, 255, 120), 32, 1.5f);
  if (type == 0) {
    // 地球图标
    dl->AddCircle(center, r * 0.55f, IM_COL32(255, 255, 255, 220), 24, 1.4f);
    dl->AddLine(ImVec2(center.x - r * 0.55f, center.y), ImVec2(center.x + r * 0.55f, center.y),
                IM_COL32(255, 255, 255, 200), 1.2f);
    dl->PathArcTo(center, r * 0.35f, -1.2f, 1.2f, 12);
    dl->PathStroke(IM_COL32(255, 255, 255, 180), 0, 1.2f);
  } else if (type == 1) {
    // 灯泡图标
    dl->AddCircleFilled(ImVec2(center.x, center.y - r * 0.15f), r * 0.38f,
                        IM_COL32(255, 255, 255, 220));
    dl->AddRectFilled(ImVec2(center.x - r * 0.22f, center.y + r * 0.18f),
                      ImVec2(center.x + r * 0.22f, center.y + r * 0.42f),
                      IM_COL32(255, 255, 255, 200), 2.0f);
  } else {
    // 盾牌/备案图标
    dl->AddRectFilled(ImVec2(center.x - r * 0.30f, center.y - r * 0.35f),
                      ImVec2(center.x + r * 0.30f, center.y + r * 0.40f),
                      IM_COL32(255, 255, 255, 220), r * 0.12f);
    dl->AddText(ImVec2(center.x - r * 0.22f, center.y - r * 0.22f),
                IM_COL32(255, 255, 255, 240), u8"备");
  }
}

static void DrawOneCard(int idx, const char *title, const char *sub, float w, float h) {
  bool active = (activeTab == idx);
  ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1, 1, 1, active ? 0.35f : 0.15f));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, DesignPx(10.0f));
  ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ScaledPanelPadding());
  ImGui::BeginChild(idx == 0 ? "card0" : "card1", ImVec2(w, h), true, ImGuiWindowFlags_NoScrollbar);

  ImVec2 winPos = ImGui::GetWindowPos();
  ImVec2 p1 = ImVec2(winPos.x + w, winPos.y + h);
  ImDrawList *dl = ImGui::GetWindowDrawList();
  
  // Use a rounded rectangle instead of sharp MultiColor rect
  if (idx == 0) {
    dl->AddRectFilled(winPos, p1, IM_COL32(37, 99, 235, 255), DesignPx(10.0f));
  } else if (idx == 1) {
    dl->AddRectFilled(winPos, p1, IM_COL32(139, 92, 246, 255), DesignPx(10.0f));
  } else {
    dl->AddRectFilled(winPos, p1, IM_COL32(20, 184, 166, 255), DesignPx(10.0f));
  }

  ImGui::SetCursorPos(ImVec2(0, 0));
  ImGui::InvisibleButton(idx == 0 ? "##cardbtn0" : "##cardbtn1", ImVec2(w, h));
  if (ImGui::IsItemClicked()) activeTab = idx;

  ImFont *bigFont = ImGui::GetIO().Fonts->Fonts.Size > 2 ? ImGui::GetIO().Fonts->Fonts[2] : ImGui::GetFont();
  ImFont *normalFont = ImGui::GetFont();

  float iconR = DesignPx(20.0f);
  float iconW = iconR * 2.0f;
  float cy = h * 0.5f;

  ImGui::PushFont(bigFont);
  float titleW = ImGui::CalcTextSize(title).x;
  ImGui::PopFont();
  float subW = ImGui::CalcTextSize(sub).x;

  float titleH = bigFont->FontSize;
  float subH = normalFont->FontSize;
  float gap = DesignPx(4.0f);
  float totalTextH = titleH + gap + subH;

  float textBlockW = std::max(titleW, subW);
  float spacing = DesignPx(16.0f);
  float totalContentW = iconW + spacing + textBlockW;
  
  float startX = (w - totalContentW) * 0.5f;

  // Draw Icon
  DrawCardIcon(dl, ImVec2(winPos.x + startX + iconR, winPos.y + cy), idx, iconR);

  // Draw Title
  float textStartX = startX + iconW + spacing;
  float textStartY = (h - totalTextH) * 0.5f;

  ImGui::SetCursorPos(ImVec2(textStartX, textStartY - DesignPx(2.0f)));
  ImGui::PushFont(bigFont);
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
  ImGui::TextUnformatted(title);
  ImGui::PopStyleColor();
  ImGui::PopFont();

  // Draw Subtitle
  ImGui::SetCursorPos(ImVec2(textStartX, textStartY + titleH + gap - DesignPx(2.0f)));
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 0.85f));
  ImGui::TextUnformatted(sub);
  ImGui::PopStyleColor();

  ImGui::EndChild();
  ImGui::PopStyleVar(3);
  ImGui::PopStyleColor(2);
}

static void DrawHeaderCards(float h) {
  float totalW = ImGui::GetContentRegionAvail().x;
  const float gap = DesignPx(kColumnGap);
  float leftCardW = totalW * 0.38f - gap * 0.67f;
  float midCardW = totalW * 0.28f - gap * 0.67f;
  float rightCardW = totalW * 0.34f - gap * 0.67f;
  DrawOneCard(0, (const char *)u8"域名扫描", (const char *)u8"扫描域名是否已注册", leftCardW, h);
  ImGui::SameLine(0, gap);
  DrawOneCard(1, (const char *)u8"域名寓意分析", (const char *)u8"分析域名寓意和价值", midCardW, h);
  ImGui::SameLine(0, gap);
  DrawOneCard(2, (const char *)u8"备案查询", (const char *)u8"查询域名ICP备案信息", rightCardW, h);
}

// ===================================================================
//  左栏布局：扫描设置 → 扫描结果表格 → 扫描日志（自上而下，约占窗口宽度 62%）
// ===================================================================
static void DrawScanSettings(float h) {
  BeginPanel("ScanSettingsBox", ImVec2(0, h));

  DrawPanelTitle((const char *)u8"扫描设置", 0);

  const float btnColW = 112.0f;
  const float colGap = 8.0f;
  const float settingsBodyH = ImGui::GetContentRegionAvail().y;
  const float leftPartW = ImGui::GetContentRegionAvail().x - btnColW - colGap;

  ImGui::BeginChild("scfgL", ImVec2(leftPartW, settingsBodyH), false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

  // 采用纵向表单布局，移除 4 列的 Table
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.0f, DesignPx(12.0f)));

  // 1. 字符类型
  ImGui::AlignTextToFramePadding();
  ImGui::TextDisabled((const char *)u8"字符类型:");
  ImGui::SameLine(DesignPx(100.0f));
  bool ct0 = (charType == 0), ct1 = (charType == 1), ct2 = (charType == 2);
  if (ImGui::Checkbox((const char *)u8"纯字母 (a-z)", &ct0)) charType = 0;
  ImGui::SameLine();
  if (ImGui::Checkbox((const char *)u8"纯数字 (0-9)", &ct1)) charType = 1;
  ImGui::SameLine();
  if (ImGui::Checkbox((const char *)u8"字母+数字 (a-z, 0-9)", &ct2)) charType = 2;

  // 2. 字符长度
  ImGui::AlignTextToFramePadding();
  ImGui::TextDisabled((const char *)u8"字符长度:");
  ImGui::SameLine(DesignPx(100.0f));
  ImGui::TextDisabled((const char *)u8"最小:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(DesignPx(140.0f));
  ImGui::InputInt("##minLen", &minLen, 1, 1);
  ImGui::SameLine(0, DesignPx(20.0f));
  ImGui::TextDisabled((const char *)u8"最大:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(DesignPx(140.0f));
  ImGui::InputInt("##maxLen", &maxLen, 1, 1);

  // 3. 字典文件与扫描参数
  ImGui::AlignTextToFramePadding();
  ImGui::TextDisabled((const char *)u8"字典参数:");
  ImGui::SameLine(DesignPx(100.0f));
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.97f, 0.98f, 0.99f, 1.0f));
  ImGui::SetNextItemWidth(DesignPx(160.0f));
  ImGui::InputText("##dict", scanDictBuf, sizeof(scanDictBuf), ImGuiInputTextFlags_ReadOnly);
  ImGui::PopStyleColor();
  ImGui::SameLine();
  ImGui::PushStyleColor(ImGuiCol_Button, kColorPrimaryBlue);
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1,1,1,1));
  if (ImGui::Button((const char *)u8"选择文件##dict")) {
    std::string fp = OpenFileDialog();
    if (!fp.empty()) {
      strncpy(scanDictBuf, fp.c_str(), sizeof(scanDictBuf) - 1);
      scanDictBuf[sizeof(scanDictBuf) - 1] = '\0';
    }
  }
  ImGui::PopStyleColor(2);
  
  // 3.5 运行参数 (新起一行)
  ImGui::AlignTextToFramePadding();
  ImGui::TextDisabled((const char *)u8"运行参数:");
  ImGui::SameLine(DesignPx(100.0f));

  ImGui::TextDisabled((const char *)u8"线程:");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(DesignPx(180.0f));
  ImGui::InputInt("##threads", &threads, 10, 100);

  ImGui::SameLine(0, DesignPx(20.0f));
  ImGui::TextDisabled((const char *)u8"超时(秒):");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(DesignPx(180.0f));
  ImGui::InputInt("##timeout", &timeout, 1, 1);

  // 4. 域名后缀
  ImGui::AlignTextToFramePadding();
  ImGui::TextDisabled((const char *)u8"域名后缀:");
  ImGui::SameLine(DesignPx(100.0f));
  ImGui::BeginGroup();
  if (ImGui::BeginTable("##extSuffix", 6, ImGuiTableFlags_None)) {
    for (int i = 0; i < 12; i++) {
      ImGui::TableNextColumn();
      ImGui::Checkbox(exts[i], &extChecks[i]);
    }
    ImGui::EndTable();
  }
  ImGui::EndGroup();

  ImGui::PopStyleVar();

  ImGui::EndChild(); // scfgL

  ImGui::SameLine(0, colGap);

  // 右侧竖排四按钮：开始/暂停/继续/停止
  const float kScanBtnGap = 8.0f;
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4.0f, 6.0f));
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, kScanBtnGap));
  ImGui::BeginChild("scfgR", ImVec2(btnColW, settingsBodyH), false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
  const float btnStackH = ImGui::GetContentRegionAvail().y;
  float bh = (btnStackH - kScanBtnGap * 3.0f) / 4.0f;
  if (bh < 26.0f) bh = 26.0f;

  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.65f, 0.25f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.75f, 0.30f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.10f, 0.55f, 0.20f, 1.0f));
  ImGui::BeginDisabled(scanIsRunning);
  if (ImGui::Button((const char *)u8"开始扫描", ImVec2(-1, bh))) StartScanAction();
  ImGui::EndDisabled();
  ImGui::PopStyleColor(4);

  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.82f, 0.60f, 0.18f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.90f, 0.68f, 0.24f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.68f, 0.49f, 0.12f, 1.0f));
  ImGui::BeginDisabled(!scanIsRunning || scanIsPaused);
  if (ImGui::Button((const char *)u8"暂停", ImVec2(-1, bh))) {
    Scanner::PauseScan();
    scanIsPaused = true;
  }
  ImGui::EndDisabled();
  ImGui::PopStyleColor(3);

  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.45f, 0.85f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25f, 0.55f, 0.95f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.05f, 0.35f, 0.75f, 1.0f));
  ImGui::BeginDisabled(!scanIsRunning || !scanIsPaused);
  if (ImGui::Button((const char *)u8"继续", ImVec2(-1, bh))) {
    Scanner::ResumeScan();
    scanIsPaused = false;
    lastTickTime = std::chrono::steady_clock::now();
  }
  ImGui::EndDisabled();
  ImGui::PopStyleColor(4);

  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.85f, 0.15f, 0.15f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.95f, 0.25f, 0.25f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.75f, 0.05f, 0.05f, 1.0f));
  ImGui::BeginDisabled(!scanIsRunning);
  if (ImGui::Button((const char *)u8"停止", ImVec2(-1, bh))) {
    Scanner::StopScan();
    scanIsRunning = false;
    scanIsPaused = false;
  }
  ImGui::EndDisabled();
  ImGui::PopStyleColor(4);

  ImGui::EndChild(); // scfgR
  ImGui::PopStyleVar(2);

  EndPanel(); // ScanSettingsBox
}

static void DrawScanResults(float h) {
  BeginPanel("ResBox", ImVec2(0, h));

  ImGui::AlignTextToFramePadding();
  ImFont *bigFont = ImGui::GetIO().Fonts->Fonts.Size > 2 ? ImGui::GetIO().Fonts->Fonts[2] : ImGui::GetFont();
  ImGui::PushFont(bigFont);
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(37.0f/255.0f, 99.0f/255.0f, 235.0f/255.0f, 1.0f));
  ImGui::TextUnformatted((const char *)u8"扫描结果 (可注册域名)");
  ImGui::PopStyleColor();
  ImGui::PopFont();
  float expW = DesignPx(100.0f);
  const float expBtnGap = DesignPx(10.0f);
  float cluster = expW * 4 + expBtnGap * 3;
  ImGui::SameLine(ImGui::GetWindowWidth() - cluster - ScaledPanelPadding().x);

  ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1,1,1,1));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f,0.95f,1.0f,1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f,0.9f,1.0f,1.0f));
  
  // 导出 TXT, CSV (Blue border)
  ImGui::PushStyleColor(ImGuiCol_Border, kColorPrimaryBlue);
  ImGui::PushStyleColor(ImGuiCol_Text, kColorPrimaryBlue);
  if (ImGui::Button((const char *)u8"导出 TXT", ImVec2(expW, 0))) ExportResults(0);
  ImGui::SameLine(0, expBtnGap);
  if (ImGui::Button((const char *)u8"导出 CSV", ImVec2(expW, 0))) ExportResults(1);
  ImGui::PopStyleColor(2);

  ImGui::SameLine(0, expBtnGap);
  // 导出 Excel (Green border)
  ImGui::PushStyleColor(ImGuiCol_Border, kColorSuccess);
  ImGui::PushStyleColor(ImGuiCol_Text, kColorSuccess);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 1.0f, 0.95f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.8f, 1.0f, 0.85f, 1.0f));
  if (ImGui::Button((const char *)u8"导出 Excel", ImVec2(expW, 0))) ExportResults(2);
  ImGui::PopStyleColor(4);

  ImGui::SameLine(0, expBtnGap);
  // 清空结果 (Red border)
  ImGui::PushStyleColor(ImGuiCol_Border, kColorDanger);
  ImGui::PushStyleColor(ImGuiCol_Text, kColorDanger);
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.9f, 0.9f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.8f, 0.8f, 1.0f));
  if (ImGui::Button((const char *)u8"清空结果", ImVec2(expW, 0))) ClearResults();
  ImGui::PopStyleColor(4);
  
  ImGui::PopStyleColor(3); // Button bg colors
  ImGui::PopStyleVar();

  ImGui::Dummy(ImVec2(0, DesignPx(4.0f)));
  ImGui::Separator();
  ImGui::Dummy(ImVec2(0, DesignPx(8.0f)));

  const float tableH = ImGui::GetContentRegionAvail().y;

  if (ImGui::BeginTable("ResTable", 6,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_ScrollX | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_Resizable,
                        ImVec2(0, tableH))) {
    ImGui::TableSetupColumn((const char *)u8"域名", ImGuiTableColumnFlags_WidthFixed, 120.0f);
    ImGui::TableSetupColumn((const char *)u8"后缀", ImGuiTableColumnFlags_WidthFixed, 55.0f);
    ImGui::TableSetupColumn((const char *)u8"状态", ImGuiTableColumnFlags_WidthFixed, 60.0f);
    ImGui::TableSetupColumn((const char *)u8"响应时间", ImGuiTableColumnFlags_WidthFixed, 75.0f);
    ImGui::TableSetupColumn((const char *)u8"注册商", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn((const char *)u8"发现时间", ImGuiTableColumnFlags_WidthFixed, 145.0f);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    std::lock_guard<std::mutex> lock(dataMutex);
    for (const auto &r : scanResults) {
      ImGui::TableNextRow();
      ImGui::TableNextColumn();
      ImGui::TextColored(kColorTextPrimary, "%s", r.domain.c_str());
      ImGui::TableNextColumn();
      ImGui::TextUnformatted(r.tld.c_str());
      ImGui::TableNextColumn();
      bool avail = (r.status == (const char *)u8"可注册");
      ImGui::TextColored(avail ? kColorSuccess : ImVec4(0.96f, 0.62f, 0.04f, 1.0f),
                         "%s", r.status.c_str());
      ImGui::TableNextColumn();
      ImGui::Text("%dms", r.responseTimeMs);
      ImGui::TableNextColumn();
      ImGui::TextUnformatted(r.registrar.c_str());
      ImGui::TableNextColumn();
      ImGui::TextDisabled("%s", FormatTimePoint(r.discoveryTime).c_str());
    }
    ImGui::EndTable();
  }

  EndPanel(); // ResBox
}

static void DrawScanLog(float h) {
  BeginPanel("LogBox", ImVec2(0, h));

  ImGui::AlignTextToFramePadding();
  ImFont *bigFont = ImGui::GetIO().Fonts->Fonts.Size > 2 ? ImGui::GetIO().Fonts->Fonts[2] : ImGui::GetFont();
  ImGui::PushFont(bigFont);
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(37.0f/255.0f, 99.0f/255.0f, 235.0f/255.0f, 1.0f));
  ImGui::TextUnformatted((const char *)u8"扫描日志");
  ImGui::PopStyleColor();
  ImGui::PopFont();
  
  ImGui::Dummy(ImVec2(0, DesignPx(4.0f)));
  ImGui::PushStyleColor(ImGuiCol_Separator, kColorPanelBorder);
  ImGui::Separator();
  ImGui::PopStyleColor();
  ImGui::Dummy(ImVec2(0, DesignPx(8.0f)));
  
  const float btnW = DesignPx(100.0f);
  const float btnH = ImGui::GetFrameHeight();
  const float listH = ImGui::GetContentRegionAvail().y - btnH - 6.0f;

  ImGui::BeginChild("LogList", ImVec2(0, listH), false, ImGuiWindowFlags_HorizontalScrollbar);
  {
    std::lock_guard<std::mutex> lock(dataMutex);
    if (ImGui::BeginTable("LogTable", 2, ImGuiTableFlags_None)) {
      ImGui::TableSetupColumn("C1", ImGuiTableColumnFlags_WidthStretch, 0.5f);
      ImGui::TableSetupColumn("C2", ImGuiTableColumnFlags_WidthStretch, 0.5f);
      for (size_t i = 0; i < logLines.size(); ++i) {
        if (i % 2 == 0) ImGui::TableNextRow();
        ImGui::TableNextColumn();
        
        const auto &line = logLines[i];
        ImVec4 dotColor = ImVec4(0.2f, 0.8f, 0.2f, 1.0f);
        if (line.find((const char *)u8"已注册") != std::string::npos ||
            line.find((const char *)u8"[FAIL]") != std::string::npos ||
            line.find((const char *)u8"Error") != std::string::npos)
          dotColor = ImVec4(0.85f, 0.3f, 0.3f, 1.0f);
        else if (line.find((const char *)u8"[INFO]") != std::string::npos ||
                 line.find((const char *)u8"扫描速度") != std::string::npos ||
                 line.find((const char *)u8"扫描进度") != std::string::npos)
          dotColor = ImVec4(0.4f, 0.65f, 1.0f, 1.0f);
        
        ImVec2 pos = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(
          ImVec2(pos.x + 4, pos.y + ImGui::GetTextLineHeight() * 0.5f), 
          3.5f, ImGui::ColorConvertFloat4ToU32(dotColor));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 12.0f);
        ImGui::TextDisabled("%s", line.c_str());
      }
      ImGui::EndTable();
    }
    if (scanIsRunning && !scanIsPaused) {
      ImGui::SetScrollHereY(1.0f);
    }
  }
  ImGui::EndChild();

  ImGui::Dummy(ImVec2(0, 2.0f));
  ImGui::SetCursorPosX(ImGui::GetWindowWidth() - btnW - ScaledPanelPadding().x);
  ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
  ImGui::PushStyleColor(ImGuiCol_Border, kColorDanger);
  ImGui::PushStyleColor(ImGuiCol_Text, kColorDanger);
  ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(1,1,1,1));
  ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.9f, 0.9f, 1.0f));
  ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.8f, 0.8f, 1.0f));
  if (ImGui::Button((const char *)u8"清空日志", ImVec2(btnW, btnH))) {
    std::lock_guard<std::mutex> lock(dataMutex);
    logLines.clear();
  }
  ImGui::PopStyleColor(5);
  ImGui::PopStyleVar();

  EndPanel(); // LogBox
}

// ===================================================================
//  右栏布局：分析配置 → 分析结果表格 → 域名详情（自上而下，约占窗口宽度 40%）
// ===================================================================
static void DrawAnaSettings(float h) {
  BeginPanel("AnaSettingsBox", ImVec2(0, h));

  DrawPanelTitle((const char *)u8"分析配置", 1);

  // 文件选择行：只读输入框 + 「选择文件」按钮
  ImGui::TextDisabled((const char *)u8"选择文件:");
  ImGui::SameLine();
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.97f, 0.98f, 0.99f, 1.0f));
  ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 96);
  ImGui::InputText("##af", analyzeFileBuf, sizeof(analyzeFileBuf), ImGuiInputTextFlags_ReadOnly);
  ImGui::PopStyleColor();
  ImGui::SameLine();
  ImGui::PushStyleColor(ImGuiCol_Button, kColorPrimaryPurple);
  ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1,1,1,1));
  if (ImGui::Button((const char *)u8"选择文件##af")) {
    std::string fp = OpenFileDialog();
    if (!fp.empty()) {
      strncpy(analyzeFileBuf, fp.c_str(), sizeof(analyzeFileBuf) - 1);
      analyzeFileBuf[sizeof(analyzeFileBuf) - 1] = '\0';
    }
  }
  ImGui::PopStyleColor(2);

  // 分析选项：3 列 x 3 行复选框网格
  ImGui::Dummy(ImVec2(0, 2.0f));
  ImGui::TextDisabled((const char *)u8"分析选项:");
  if (ImGui::BeginTable("anaOpts", 3, ImGuiTableFlags_None)) {
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"拼音分析", &anaOpt[0]);
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"英文单词分析", &anaOpt[1]);
    
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"品牌价值分析", &anaOpt[2]);
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"SEO价值分析", &anaOpt[3]);
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"行业关联分析", &anaOpt[4]);
    
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"数字价值分析", &anaOpt[5]);
    ImGui::TableNextColumn();
    ImGui::Checkbox((const char *)u8"数字含义分析", &anaOpt[6]);
    ImGui::EndTable();
  }

  ImGui::Dummy(ImVec2(0, DesignPx(4.0f)));
  if (meaningAnalysisRunning) {
      ImGui::BeginDisabled();
      char btnTxt[64];
      snprintf(btnTxt, sizeof(btnTxt), (const char*)u8"分析中 %d / %d", (int)meaningAnalysisProgress, (int)meaningAnalysisTotal);
      ImGui::Button(btnTxt, ImVec2(-1, 34));
      ImGui::EndDisabled();
      
      float progress = 0.0f;
      if (meaningAnalysisTotal > 0) progress = (float)meaningAnalysisProgress / meaningAnalysisTotal;
      ImGui::ProgressBar(progress, ImVec2(-1, 4.0f), "");
  } else {
      ImGui::PushStyleColor(ImGuiCol_Button, kColorPrimaryPurple);
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.62f, 0.42f, 0.98f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.46f, 0.28f, 0.86f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
      if (ImGui::Button((const char *)u8"开始分析", ImVec2(-1, 34))) AnalyzeDomains(analyzeFileBuf);
      ImGui::PopStyleColor(4);
  }

  EndPanel(); // AnaSettingsBox
}

static void DrawAnaResults(float h) {
  BeginPanel("AnaResultBox", ImVec2(0, h));

  DrawPanelTitle((const char *)u8"分析结果", 1);

  const float tableH = ImGui::GetContentRegionAvail().y;

  if (ImGui::BeginTable("AnaTable", 3,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                            ImGuiTableFlags_Borders,
                        ImVec2(0, tableH))) {
    ImGui::TableSetupColumn((const char *)u8"域名", ImGuiTableColumnFlags_WidthFixed, 120.0f);
    ImGui::TableSetupColumn((const char *)u8"寓意分析 (部分)", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn((const char *)u8"综合评分", ImGuiTableColumnFlags_WidthFixed, 64.0f);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    std::lock_guard<std::mutex> lock(dataMutex);
    for (size_t i = 0; i < analysisResults.size(); i++) {
      const auto &res = analysisResults[i];
      bool isSelected = (selectedAnalysisIdx == (int)i);
      ImGui::TableNextRow();
      ImGui::TableNextColumn();
      if (isSelected) ImGui::PushStyleColor(ImGuiCol_Text, kColorDanger); // Highlighting red in design
      if (ImGui::Selectable(res.domain.c_str(), isSelected,
                            ImGuiSelectableFlags_SpanAllColumns))
        selectedAnalysisIdx = (int)i;
      if (isSelected) ImGui::PopStyleColor();
      ImGui::TableNextColumn();
      ImGui::TextUnformatted(res.meaning.c_str());
      ImGui::TableNextColumn();
      ImGui::TextColored(kColorDanger, "%d", res.score);
    }
    ImGui::EndTable();
  }

  EndPanel(); // AnaResultBox
}

static ImU32 LerpColorU32(ImU32 a, ImU32 b, float k) {
  int ar = (a >> IM_COL32_R_SHIFT) & 0xFF, ag = (a >> IM_COL32_G_SHIFT) & 0xFF,
      ab = (a >> IM_COL32_B_SHIFT) & 0xFF, aa = (a >> IM_COL32_A_SHIFT) & 0xFF;
  int br = (b >> IM_COL32_R_SHIFT) & 0xFF, bg = (b >> IM_COL32_G_SHIFT) & 0xFF,
      bb = (b >> IM_COL32_B_SHIFT) & 0xFF, ba = (b >> IM_COL32_A_SHIFT) & 0xFF;
  return IM_COL32((int)(ar + (br - ar) * k), (int)(ag + (bg - ag) * k),
                  (int)(ab + (bb - ab) * k), (int)(aa + (ba - aa) * k));
}

static void DrawScoreGauge(ImDrawList *dl, ImVec2 center, float radius, int score) {
  float t = score / 100.0f;
  if (t < 0) t = 0;
  if (t > 1) t = 1;
  dl->AddCircle(center, radius, IM_COL32(226, 232, 240, 255), 64, 7.0f);
  const float kPi = 3.14159265358979f;
  float a0 = -kPi / 2.0f;
  float a1 = a0 + t * 2.0f * kPi;
  // Gradient progress arc (red -> yellow -> blue) to match the design mock.
  const ImU32 cStart = IM_COL32(239, 68, 68, 255);   // Red
  const ImU32 cMid = IM_COL32(245, 158, 11, 255);    // Yellow/Orange
  const ImU32 cEnd = IM_COL32(59, 130, 246, 255);    // Blue
  const int segs = 96;
  for (int i = 0; i < segs; i++) {
    float k0 = (float)i / segs, k1 = (float)(i + 1) / segs;
    float kc = (k0 + k1) * 0.5f;
    ImU32 col = (kc < 0.5f) ? LerpColorU32(cStart, cMid, kc / 0.5f)
                            : LerpColorU32(cMid, cEnd, (kc - 0.5f) / 0.5f);
    dl->PathArcTo(center, radius, a0 + (a1 - a0) * k0, a0 + (a1 - a0) * k1, 4);
    dl->PathStroke(col, 0, 7.0f);
  }

  char num[16];
  snprintf(num, sizeof(num), "%d", score);
  ImFont *big = ImGui::GetIO().Fonts->Fonts[1];
  ImVec2 ns = big->CalcTextSizeA(big->FontSize, FLT_MAX, 0.0f, num);
  dl->AddText(big, big->FontSize,
              ImVec2(center.x - ns.x * 0.5f, center.y - ns.y * 0.5f - 6.0f),
              IM_COL32(30, 41, 59, 255), num);

  const char *lab = (const char *)u8"综合评分";
  ImVec2 ls = ImGui::CalcTextSize(lab);
  dl->AddText(ImVec2(center.x - ls.x * 0.5f, center.y + radius * 0.34f),
              IM_COL32(100, 116, 139, 255), lab);
}

static void DrawDomainDetail(float h) {
  BeginPanel("DetailBox", ImVec2(0, h), 0);

  DrawPanelTitle((const char *)u8"域名详情", 1);

  std::lock_guard<std::mutex> lock(dataMutex);
  if (selectedAnalysisIdx >= 0 && selectedAnalysisIdx < (int)analysisResults.size()) {
    const auto &res = analysisResults[selectedAnalysisIdx];

    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[1]);
    ImGui::TextColored(kColorPrimaryPurple, "%s", res.domain.c_str());
    ImGui::PopFont();

    // 左侧文字详情区：标签列宽 86px，右侧预留给圆环评分
    float alignX = 86.0f;
    float wrapX = ImGui::GetContentRegionAvail().x - 110.0f;

    ImGui::TextDisabled((const char *)u8"拼音:");
    ImGui::SameLine(alignX);
    ImGui::TextUnformatted(res.pinyin.c_str());

    ImGui::TextDisabled((const char *)u8"含义:");
    ImGui::SameLine(alignX);
    ImGui::PushTextWrapPos(wrapX);
    ImGui::TextWrapped("%s", res.meaning.c_str());
    ImGui::PopTextWrapPos();

    ImGui::TextDisabled((const char *)u8"行业:");
    ImGui::SameLine(alignX);
    ImGui::PushTextWrapPos(wrapX);
    ImGui::TextWrapped("%s", res.industry.c_str());
    ImGui::PopTextWrapPos();

    ImGui::TextDisabled((const char *)u8"品牌价值:");
    ImGui::SameLine(alignX);
    ImGui::TextColored(ImVec4(0.96f, 0.62f, 0.04f, 1.0f), "%s",
                       GetStarsString(res.score).c_str());

    ImGui::TextDisabled((const char *)u8"SEO价值:");
    ImGui::SameLine(alignX);
    ImGui::TextColored(ImVec4(0.96f, 0.62f, 0.04f, 1.0f), "%s",
                       GetStarsString(res.seoScore).c_str());

    ImGui::TextDisabled((const char *)u8"推荐指数:");
    ImGui::SameLine(alignX);
    ImGui::TextColored(ImVec4(0.96f, 0.62f, 0.04f, 1.0f), "%s",
                       GetStarsString(res.score).c_str());

    // 右侧圆环综合评分（锚点随面板高度自适应，避免底部被裁切）
    ImVec2 boxMin = ImGui::GetWindowPos();
    float boxW = ImGui::GetWindowWidth();
    float boxH = ImGui::GetWindowHeight();
    float gaugeY = boxMin.y + std::min(116.0f, std::max(72.0f, boxH - 48.0f));
    ImVec2 center = ImVec2(boxMin.x + boxW - 70.0f, gaugeY);
    DrawScoreGauge(ImGui::GetWindowDrawList(), center, 44.0f, res.score);
  } else {
    ImGui::TextDisabled((const char *)u8"暂无详细域名信息。请在上方选择一个域名查看分析详情。");
  }

  EndPanel(); // DetailBox
}

// ===================================================================
//  底部状态栏：运行状态、总进度条、已扫描/可注册计数、运行时间
// ===================================================================
static void DrawFooter(float h) {
  ImGui::PushStyleColor(ImGuiCol_ChildBg, kColorTitleBarBg);
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(DesignPx(kContentPadX), 0));
  ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
  ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
  ImGui::BeginChild("Footer", ImVec2(0, h), false, ImGuiWindowFlags_NoScrollbar);

  float footerW = ImGui::GetWindowWidth();
  ImVec2 winPos = ImGui::GetWindowPos();
  float itemY = (h - ImGui::GetTextLineHeight()) * 0.5f;

  // Status
  const char *statusTxt;
  ImU32 dotCol;
  if (scanIsRunning && !scanIsPaused) {
    statusTxt = (const char *)u8"扫描中...";
    dotCol = IM_COL32(60, 170, 255, 255);
  } else if (scanIsRunning && scanIsPaused) {
    statusTxt = (const char *)u8"已暂停";
    dotCol = IM_COL32(230, 190, 50, 255);
  } else {
    statusTxt = (const char *)u8"就绪";
    dotCol = IM_COL32(50, 210, 90, 255);
  }
  ImGui::GetWindowDrawList()->AddCircleFilled(
      ImVec2(winPos.x + 14, winPos.y + h * 0.5f), 4.5f, dotCol);
  ImGui::SetCursorPos(ImVec2(28, itemY));
  ImGui::TextColored(ImVec4(1, 1, 1, 0.95f), "%s", statusTxt);

  // Metrics
  long long scanned = (long long)Scanner::GetScannedCount();
  long long avail = (long long)Scanner::GetAvailableCount();
  float speed = Scanner::GetScansPerSecond();
  float progress = currentTotalDomains > 0
                       ? (float)((double)scanned / (double)currentTotalDomains)
                       : 0.0f;
  if (progress > 1.0f) progress = 1.0f;
  int elapsed = elapsedSeconds;
  int hrs = elapsed / 3600, mins = (elapsed % 3600) / 60, secs = elapsed % 60;
  char timeStr[32];
  snprintf(timeStr, sizeof(timeStr), "%02d:%02d:%02d", hrs, mins, secs);
  char pctBuf[16];
  snprintf(pctBuf, sizeof(pctBuf), "%.0f%%", progress * 100.0f);
  char speedBuf[32];
  snprintf(speedBuf, sizeof(speedBuf), "%.0f/s", speed);
  std::string s1 = FormatNumberWithCommas(scanned);
  long long remaining = currentTotalDomains > scanned ? currentTotalDomains - scanned : 0;
  std::string sRem = FormatNumberWithCommas(remaining);
  std::string s2 = FormatNumberWithCommas(avail);

  const ImVec4 lbl = ImVec4(1, 1, 1, 0.72f);
  const ImVec4 val = ImVec4(1, 1, 1, 0.95f);

  auto FooterMetric = [&](float xRatio, const char *label, const char *value, ImVec4 valueColor) {
    ImGui::SetCursorPos(ImVec2(footerW * xRatio, itemY));
    ImGui::TextColored(lbl, "%s", label);
    ImGui::SameLine(0, 4);
    ImGui::TextColored(valueColor, "%s", value);
  };

  FooterMetric(0.20f, (const char *)u8"总进度:", pctBuf, val);
  
  float pbX = footerW * 0.20f + ImGui::CalcTextSize((const char *)u8"总进度:").x + 4 + ImGui::CalcTextSize(pctBuf).x + DesignPx(8.0f);
  ImGui::SetCursorPos(ImVec2(pbX, (h - 10.0f) * 0.5f));
  ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(1.0f, 1.0f, 1.0f, 0.95f));
  ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(1.0f, 1.0f, 1.0f, 0.22f));
  ImGui::ProgressBar(progress, ImVec2(DesignPx(150.0f), 10.0f), "");
  ImGui::PopStyleColor(2);

  FooterMetric(0.40f, (const char *)u8"已扫描:", s1.c_str(), val);
  FooterMetric(0.55f, (const char *)u8"剩余:", sRem.c_str(), val);
  FooterMetric(0.70f, (const char *)u8"可注册:", s2.c_str(), ImVec4(0.75f, 1.0f, 0.85f, 1.0f));
  FooterMetric(0.85f, (const char *)u8"运行时间:", timeStr, val);

  ImGui::EndChild();
  ImGui::PopStyleVar(3);
  ImGui::PopStyleColor();
}

// ===================================================================
//  主渲染入口：整页垂直分区（标题栏 → 主体 → 底栏）+ 主体内左右分栏
// ===================================================================
// ===================================================================
//  ICP备案查询面板
// ===================================================================
static void DrawIcpPanel() {
  InitIcpApiUrl();

  BeginPanel("IcpSettingsBox", ImVec2(0, 0));
  DrawPanelTitle((const char*)u8"ICP备案查询", 2);

  float panelW = ImGui::GetContentRegionAvail().x;

  // --- 第一行：输入方式 ---
  ImGui::TextUnformatted((const char*)u8"域名输入:");
  ImGui::SameLine();
  ImGui::PushItemWidth(panelW * 0.35f);
  ImGui::InputTextWithHint("##icpInput", (const char*)u8"每行一个域名，或粘贴域名列表...",
                           icpInputBuf, sizeof(icpInputBuf));
  ImGui::PopItemWidth();
  ImGui::SameLine();
  if (ImGui::Button((const char*)u8"从文件导入", ImVec2(100, 0))) {
    OPENFILENAMEA ofn = {sizeof(ofn)};
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFilter = "Text Files\0*.txt\0CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrFile = icpDictPathBuf;
    ofn.nMaxFile = sizeof(icpDictPathBuf);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameA(&ofn)) {
      std::ifstream file(icpDictPathBuf);
      if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        file.close();
        strncpy(icpInputBuf, content.c_str(), sizeof(icpInputBuf) - 1);
      }
    }
  }

  // --- 第二行：API设置 + 过滤 ---
  ImGui::Spacing();
  if (ImGui::CollapsingHeader((const char*)u8"API 设置")) {
    ImGui::TextUnformatted((const char*)u8"API地址:");
    ImGui::SameLine();
    ImGui::PushItemWidth(panelW * 0.55f);
    if (ImGui::InputTextWithHint("##icpApiUrl",
          (const char*)u8"https://api.uomg.com/api/icp",
          icpApiUrlBuf, sizeof(icpApiUrlBuf))) {
      icpApiConfigured = true;
    }
    ImGui::PopItemWidth();
    ImGui::SameLine();
    ImGui::TextDisabled((const char*)u8"(?)");
    if (ImGui::IsItemHovered())
      ImGui::SetTooltip((const char*)u8"免费ICP备案查询API\n默认: api.uomg.com\n也可用: api.vvhan.com/api/icp\n需要注册: apihz.cn, tianapi.com");
  }

  ImGui::Spacing();

  // --- 过滤选项 ---
  ImGui::TextUnformatted((const char*)u8"显示过滤:");
  ImGui::SameLine();
  ImGui::Checkbox((const char*)u8"已备案", &icpShowHasIcp);
  ImGui::SameLine();
  ImGui::Checkbox((const char*)u8"未备案", &icpShowNoIcp);
  ImGui::SameLine();
  ImGui::Checkbox((const char*)u8"错误", &icpShowError);

  ImGui::SameLine(0, 30);
  ImGui::TextUnformatted((const char*)u8"域名长度:");
  ImGui::SameLine();
  ImGui::PushItemWidth(50);
  ImGui::InputInt("##icpMinLen", &icpFilterMinLen, 0);
  ImGui::PopItemWidth();
  ImGui::SameLine();
  ImGui::TextUnformatted("-");
  ImGui::SameLine();
  ImGui::PushItemWidth(50);
  ImGui::InputInt("##icpMaxLen", &icpFilterMaxLen, 0);
  ImGui::PopItemWidth();

  // --- 扫描按钮 ---
  ImGui::Spacing();
  bool canStart = !icpScanRunning.load() && strlen(icpInputBuf) > 0;
  if (!canStart) ImGui::BeginDisabled();
  if (ImGui::Button((const char*)u8"开始查询备案", ImVec2(130, 32))) {
    // 解析输入域名
    std::vector<std::string> domains;
    std::string input(icpInputBuf);
    std::stringstream ss(input);
    std::string line;
    while (std::getline(ss, line)) {
      // 去除空白
      line.erase(0, line.find_first_not_of(" \t\r\n"));
      line.erase(line.find_last_not_of(" \t\r\n") + 1);
      if (line.empty()) continue;
      int len = (int)line.size();
      if (len >= icpFilterMinLen && len <= icpFilterMaxLen) {
        domains.push_back(line);
      }
    }
    if (!domains.empty()) {
      icpResults.clear();
      icpScanStartTime = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now().time_since_epoch()).count();
      icpScanner.setApiUrl(icpApiUrlBuf);
      icpScanner.startScan(domains,
        [](int current, int total, const DomainSniper::IcpResult& result) {
          icpScanProgress = current;
          icpScanTotal = total;
          std::lock_guard<std::mutex> lock(icpMutex);
          icpResults.push_back(result);
        },
        [](const std::vector<DomainSniper::IcpResult>&) {
          icpScanRunning = false;
        });
      icpScanRunning = true;
    }
  }
  if (!canStart) ImGui::EndDisabled();

  ImGui::SameLine();
  if (icpScanRunning.load()) {
    if (ImGui::Button((const char*)u8"停止查询", ImVec2(100, 32))) {
      icpScanner.stopScan();
      icpScanRunning = false;
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f),
        (const char*)u8"查询中... %d/%d", icpScanProgress.load(), icpScanTotal.load());
  } else if (!icpResults.empty()) {
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.3f, 0.8f, 0.3f, 1.0f),
        (const char*)u8"完成 %d 条", (int)icpResults.size());
  }

  // --- 快速导入到WHOIS扫描 ---
  if (!icpResults.empty() && !icpScanRunning.load()) {
    ImGui::SameLine();
    if (ImGui::Button((const char*)u8"已备案域名 → WHOIS扫描", ImVec2(170, 28))) {
      std::vector<DomainSniper::IcpResult> toImport;
      for (const auto& r : icpResults) {
        if (r.hasIcp) toImport.push_back(r);
      }
      ImportIcpToScan(toImport);
    }
  }

  ImGui::EndChild();
  // ── 结果表格 ──
  ImGui::Spacing();
  float tableH = ImGui::GetContentRegionAvail().y - DesignPx(10.0f);
  if (tableH < DesignPx(100.0f)) tableH = DesignPx(100.0f);

  BeginPanel("IcpResultsBox", ImVec2(0, tableH));
  DrawPanelTitle((const char*)u8"查询结果", 2);

  ImGui::BeginChild("IcpResultsScroll", ImVec2(0, ImGui::GetContentRegionAvail().y - DesignPx(5.0f)),
                    false, ImGuiWindowFlags_HorizontalScrollbar);

  if (ImGui::BeginTable("IcpResultTable", 7,
        ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_Sortable)) {
    ImGui::TableSetupColumn((const char*)u8"域名", ImGuiTableColumnFlags_WidthFixed, 150.0f);
    ImGui::TableSetupColumn((const char*)u8"备案状态", ImGuiTableColumnFlags_WidthFixed, 80.0f);
    ImGui::TableSetupColumn((const char*)u8"备案号", ImGuiTableColumnFlags_WidthFixed, 160.0f);
    ImGui::TableSetupColumn((const char*)u8"主办单位", ImGuiTableColumnFlags_WidthFixed, 200.0f);
    ImGui::TableSetupColumn((const char*)u8"类型", ImGuiTableColumnFlags_WidthFixed, 60.0f);
    ImGui::TableSetupColumn((const char*)u8"审核时间", ImGuiTableColumnFlags_WidthFixed, 100.0f);
    ImGui::TableSetupColumn((const char*)u8"响应(ms)", ImGuiTableColumnFlags_WidthFixed, 70.0f);
    ImGui::TableHeadersRow();

    std::lock_guard<std::mutex> lock(icpMutex);
    for (const auto& r : icpResults) {
      // 过滤
      if (!icpShowHasIcp && r.hasIcp) continue;
      if (!icpShowNoIcp && !r.hasIcp && r.success) continue;
      if (!icpShowError && !r.success) continue;

      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextUnformatted(r.domain.c_str());

      ImGui::TableSetColumnIndex(1);
      if (r.hasIcp) {
        ImGui::TextColored(ImVec4(0.1f, 0.8f, 0.3f, 1.0f), (const char*)u8"已备案");
      } else if (r.success) {
        ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), (const char*)u8"未备案");
      } else {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), (const char*)u8"错误");
      }

      ImGui::TableSetColumnIndex(2);
      ImGui::TextUnformatted(r.icpNumber.c_str());

      ImGui::TableSetColumnIndex(3);
      ImGui::TextUnformatted(r.companyName.c_str());

      ImGui::TableSetColumnIndex(4);
      ImGui::TextUnformatted(r.companyType.c_str());

      ImGui::TableSetColumnIndex(5);
      ImGui::TextUnformatted(r.auditTime.c_str());

      ImGui::TableSetColumnIndex(6);
      ImGui::Text("%d", r.responseTimeMs);
    }
    ImGui::EndTable();
  }
  ImGui::EndChild();
  ImGui::EndChild();
}

void MainWindow::Render(GLFWwindow *window) {
  // 扫描运行计时：仅在「运行中且未暂停」时累加秒数
  auto tickNow = std::chrono::steady_clock::now();
  if (scanIsRunning && !scanIsPaused) {
    static double accumulatedDelta = 0.0;
    double delta = std::chrono::duration<double>(tickNow - lastTickTime).count();
    accumulatedDelta += delta;
    if (accumulatedDelta >= 1.0) {
      elapsedSeconds += (int)accumulatedDelta;
      accumulatedDelta -= (int)accumulatedDelta;
    }
  }
  lastTickTime = tickNow;

  ImGuiIO &io = ImGui::GetIO();
  ImGui::SetNextWindowPos(ImVec2(0, 0));
  ImGui::SetNextWindowSize(io.DisplaySize);

  ImGuiWindowFlags window_flags =
      ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
      ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

  ImGuiStyle &style = ImGui::GetStyle();
  style.Colors[ImGuiCol_WindowBg] = kColorBodyBg;
  style.Colors[ImGuiCol_Text] = kColorTextPrimary;
  style.Colors[ImGuiCol_ChildBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
  style.Colors[ImGuiCol_Border] = kColorPanelBorder;
  style.Colors[ImGuiCol_Button] = ImVec4(0.94f, 0.96f, 0.98f, 1.0f);
  style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.88f, 0.92f, 0.97f, 1.0f);
  style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.82f, 0.88f, 0.95f, 1.0f);
  style.Colors[ImGuiCol_Header] = ImVec4(0.94f, 0.96f, 0.99f, 1.0f);
  style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.88f, 0.92f, 0.97f, 1.0f);
  style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.82f, 0.88f, 0.95f, 1.0f);
  style.Colors[ImGuiCol_CheckMark] = kColorPrimaryBlue;
  style.Colors[ImGuiCol_FrameBg] = ImVec4(0.97f, 0.98f, 0.99f, 1.0f);
  style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.94f, 0.96f, 0.98f, 1.0f);
  style.Colors[ImGuiCol_TextDisabled] = kColorTextSecondary;
  style.Colors[ImGuiCol_TableHeaderBg] = ImVec4(0.96f, 0.97f, 0.99f, 1.0f);
  style.Colors[ImGuiCol_TableBorderLight] = kColorPanelBorder;
  style.Colors[ImGuiCol_TableBorderStrong] = ImVec4(0.82f, 0.88f, 0.94f, 1.0f);
  style.Colors[ImGuiCol_TableRowBg] = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
  style.Colors[ImGuiCol_TableRowBgAlt] = ImVec4(0.98f, 0.99f, 1.0f, 1.0f);
  style.Colors[ImGuiCol_Separator] = kColorPanelBorder;
  style.WindowBorderSize = 0.0f;
  style.WindowRounding = 0.0f;
  style.ChildRounding = 8.0f;
  style.FrameRounding = 5.0f;
  style.ChildBorderSize = 1.0f;
  style.WindowPadding = ImVec2(8.0f, 6.0f);
  style.FramePadding = ImVec2(6.0f, 4.0f);
  style.ItemSpacing = ImVec2(8.0f, 6.0f);
  style.ItemInnerSpacing = ImVec2(6.0f, 4.0f);
  style.CellPadding = ImVec2(8.0f, 5.0f);
  style.IndentSpacing = 18.0f;

  // 根窗口铺满整个 GLFW 视口，无系统标题栏（自定义 DrawTitleBar）
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::Begin("MainDashboard", nullptr, window_flags);
  ImGui::PopStyleVar();

  // 各区域固定高度（规范 1600×900 基准，随窗口等比缩放）
  const float kTitleH = DesignPx(48.0f);
  const float kFooterH = DesignPx(40.0f);
  const float kBodyPadX = DesignPx(kContentPadX);
  const float kBodyPadY = DesignPx(kContentPadY);
  const float kScaledSectionGap = DesignPx(kSectionGap);
  const float kScaledColumnGap = DesignPx(kColumnGap);

  // ── 区域 1：顶部标题栏（贴顶、全宽、无圆角）──
  ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x, 0.0f));
  DrawTitleBar(window, kTitleH);

  // ── 区域 2：主体 Body（预先扣除 Footer 高度，Footer 贴底）──
  const float footerReserve = kFooterH;
  const float bodyH = ImGui::GetContentRegionAvail().y - footerReserve;
  const ImGuiWindowFlags kFixedChildFlags =
      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(kBodyPadX, kBodyPadY));
  ImGui::BeginChild("Body", ImVec2(0, std::max(DesignPx(100.0f), bodyH)), ImGuiChildFlags_AlwaysUseWindowPadding,
                    kFixedChildFlags);

  // ── 中间 Content（包含顶部卡片）──
  float contentH = ImGui::GetContentRegionAvail().y;
  if (contentH < DesignPx(80.0f)) contentH = DesignPx(80.0f);
  ImGui::BeginChild("Content", ImVec2(0, contentH), ImGuiChildFlags_None, kFixedChildFlags);

  const float kCardH = DesignPx(80.0f);
  DrawHeaderCards(kCardH);
  ImGui::Dummy(ImVec2(0, kScaledSectionGap));

  // ── 备案查询Tab（全宽面板）──
  if (activeTab == 2) {
    DrawIcpPanel();
    ImGui::EndChild(); // Content
    ImGui::EndChild(); // Body
    ImGui::PopStyleVar();
    DrawFooter(kFooterH);
    ImGui::PopStyleVar();
    ImGui::End();
    return;
  }

  const float colH = ImGui::GetContentRegionAvail().y;
  float totalW = ImGui::GetContentRegionAvail().x;
  float leftW = totalW * 0.60f - kScaledColumnGap * 0.5f;
  float rightW = totalW * 0.40f - kScaledColumnGap * 0.5f;

  // ── 左栏 LeftCol（60% 宽）：扫描设置 → 扫描结果 → 扫描日志 ──
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::BeginChild("LeftCol", ImVec2(leftW, colH), false, kFixedChildFlags);
  ImGui::PopStyleVar();
  {
    float leftColH = ImGui::GetContentRegionAvail().y;
    const float stackGap = kScaledSectionGap;
    const float stackGaps = stackGap * 2.0f;
    const float kScanCfgFixedH = GetScanCfgFixedH();
    const float kResPanelHeaderH =
        ImGui::GetFrameHeightWithSpacing() + DesignPx(10.0f) + DesignPx(kPanelPadding.y) * 2.0f;
    const float kLogMinH = DesignPx(kMinLogPanelH);
    const float kResBodyMinH = DesignPx(kMinResTableBodyH);

    int scanRowCount = 0;
    {
      std::lock_guard<std::mutex> lock(dataMutex);
      scanRowCount = (int)scanResults.size();
    }

    float cfgH = kScanCfgFixedH;
    const float kResPanelMinH = kResPanelHeaderH + kResBodyMinH;
    float resH = std::max(kResPanelMinH, leftColH * kScanResColRatio);
    float logH = leftColH - cfgH - resH - stackGaps;

    if (logH < kLogMinH) {
      resH = std::max(kResPanelMinH, leftColH - cfgH - kLogMinH - stackGaps);
      logH = leftColH - cfgH - resH - stackGaps - DesignPx(2.0f);
    }
    FitColumnPanels(leftColH, stackGap, cfgH, resH, logH, kScanCfgFixedH, kResPanelMinH, kLogMinH);
    logH = leftColH - cfgH - resH - stackGaps - DesignPx(2.0f);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x, 0.0f));
    DrawScanSettings(cfgH);
    ImGui::Dummy(ImVec2(0, stackGap));
    DrawScanResults(resH);
    ImGui::Dummy(ImVec2(0, stackGap));
    DrawScanLog(logH);
    ImGui::PopStyleVar();
  }
  ImGui::EndChild();

  ImGui::SameLine(0, kScaledColumnGap);

  // ── 右栏 RightCol（40% 宽）：分析配置 → 分析结果 → 域名详情 ──
  ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
  ImGui::BeginChild("RightCol", ImVec2(rightW, colH), false, kFixedChildFlags);
  ImGui::PopStyleVar();
  {
    float rightColH = ImGui::GetContentRegionAvail().y;
    const float stackGap = kScaledSectionGap;
    const float stackGaps = stackGap * 2.0f;
    const float kAnaCfgFixedH = GetAnaCfgFixedH();
    const float kAnaResHeaderH =
        ImGui::GetTextLineHeightWithSpacing() + DesignPx(8.0f) + DesignPx(kPanelPadding.y) * 2.0f;
    const float kDetailMinH = DesignPx(kMinDetailPanelH);
    const float kAnaBodyMinH = DesignPx(kMinAnaTableBodyH);

    int anaRowCount = 0;
    {
      std::lock_guard<std::mutex> lock(dataMutex);
      anaRowCount = (int)analysisResults.size();
    }

    float anaCfgH = kAnaCfgFixedH;
    const float kAnaPanelMinH = kAnaResHeaderH + kAnaBodyMinH;
    float anaTableH = std::max(kAnaPanelMinH, rightColH * kAnaResColRatio);
    float detailH = rightColH - anaCfgH - anaTableH - stackGaps;

    if (detailH < kDetailMinH) {
      anaTableH = std::max(kAnaPanelMinH, rightColH - anaCfgH - kDetailMinH - stackGaps);
      detailH = rightColH - anaCfgH - anaTableH - stackGaps - DesignPx(2.0f);
    }
    FitColumnPanels(rightColH, stackGap, anaCfgH, anaTableH, detailH, kAnaCfgFixedH, kAnaPanelMinH,
                    kDetailMinH);
    detailH = rightColH - anaCfgH - anaTableH - stackGaps - DesignPx(2.0f);

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x, 0.0f));
    DrawAnaSettings(anaCfgH);
    ImGui::Dummy(ImVec2(0, stackGap));
    DrawAnaResults(anaTableH);
    ImGui::Dummy(ImVec2(0, stackGap));
    DrawDomainDetail(detailH);
    ImGui::PopStyleVar();
  }
  ImGui::EndChild();

  ImGui::EndChild(); // Content

  ImGui::EndChild(); // Body
  ImGui::PopStyleVar();

  // ── 区域 4：底部 Footer（贴底、全宽、无圆角）──
  DrawFooter(kFooterH);

  ImGui::PopStyleVar(); // ItemSpacing.y = 0

  ImGui::End(); // MainDashboard
}
