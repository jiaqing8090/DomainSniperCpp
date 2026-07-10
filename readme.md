# 未注册域名扫描工具 (DomainSniperCpp)

一款 Windows 桌面应用：批量扫描域名是否可注册，并对可注册域名做“寓意 / 价值”分析。界面按设计图重做为深色双栏风格。

## 技术栈

- C++20
- [Dear ImGui](https://github.com/ocornut/imgui) v1.90.9（即时模式 GUI）
- [GLFW](https://github.com/glfw/glfw) 3.4 + OpenGL3 后端
- CMake（FetchContent 拉取依赖）+ MinGW-w64 (UCRT) 工具链
- WHOIS 查询基于 Winsock2 (ws2_32)，多线程并发

## 目录结构

```
DomainSniperCpp/
├─ main.cpp              # 入口：创建无边框 GLFW 窗口、加载字体、主循环
├─ engine/
│  ├─ Scanner.{h,cpp}    # 多线程 WHOIS 扫描引擎
│  └─ Dictionary.{h,cpp} # 英文词典（内存映射 ecdict.csv）
├─ ui/
│  └─ MainWindow.{h,cpp} # 全部界面（标题栏/双栏/状态栏）+ 寓意分析逻辑
├─ assets/ecdict.csv     # 英文词典数据
├─ CMakeLists.txt
└─ build/                # 构建产物（DomainSniperCpp.exe）
```

## 构建与运行

需要已安装 CMake 与 MinGW-w64 (WinLibs UCRT)。

```bash
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build -j 4
./build/DomainSniperCpp.exe
```

## 界面（按设计图重设计）

- **自绘深色标题栏**：应用图标 + 标题 + `设置` / `帮助` 弹窗 + 最小化/最大化/关闭；可拖拽移动，双击标题栏最大化/还原（无边框窗口，原生 `WM_NCLBUTTONDOWN` 拖动）。
- **左栏「域名扫描」（蓝色）**
  - 扫描设置：字符类型（纯字母 / 纯数字 / 字母+数字）、字符长度（最小/最大）、字典文件、扫描线程、超时时间、域名后缀多选（12 个 TLD）；右侧竖排「开始扫描 / 暂停 / 继续 / 停止」。
  - 扫描结果（可注册域名）表：域名 / 后缀 / 状态 / 响应时间 / 注册商 / 发现时间；支持导出 TXT / CSV / Excel、清空结果。
  - 扫描日志：彩色状态点 + 实时日志。
- **右栏「域名寓意分析」（紫色）**
  - 分析配置：选择文件、6 项分析选项、`开始分析`。
  - 分析结果表：域名 / 寓意分析 / 综合评分（可点选）。
  - 域名详情：拼音、含义、行业、品牌价值 / SEO 价值 / 推荐指数（星级）+ 环形综合评分仪表盘。
- **底部状态栏**：状态指示、总进度条、已扫描、可注册、运行时间（首次启动展示与设计图一致的演示数据）。

## 扫描模式

- **字典模式**：在“字典文件”选择一个每行一个前缀的 txt，与勾选的后缀组合扫描。
- **内存生成模式**：当字典文件为空/不可读时，按“字符类型 + 字符长度”自动生成前缀进行扫描。

## 寓意分析

对可注册域名前缀依次匹配：纯数字 → 英文单词（词典）→ 极品词组（双拼/缩写）→ 纯双拼 → 特殊规律（AABB/顺子等），输出综合评分与星级，并按分类写入 `results_meaning/` 目录。

## 备注

- 字体使用系统 `C:\Windows\Fonts\msyh.ttc`（微软雅黑），加载 20px / 42px / 26px 三种字号。
- WHOIS 服务器按 TLD 选择，结果判断为简单关键字匹配，仅供参考。
