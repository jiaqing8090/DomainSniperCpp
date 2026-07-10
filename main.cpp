#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <iostream>
#include <vector>
#include "ui/stb_image.h"
#include "MainWindow.h"
#include "Dictionary.h"

#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#include <dwmapi.h>
#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_BORDER_COLOR
#define DWMWA_BORDER_COLOR 34
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWCP_DONOTROUND
#define DWMWCP_DONOTROUND 1
#endif
#endif

// GLFW 错误回调：将底层图形库错误输出到 stderr
static void glfw_error_callback(int error, const char* description)
{
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

int main(int, char**)
{
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    // 选择 OpenGL / GLSL 版本（macOS 需 Core Profile + Forward Compatible）
#if defined(__APPLE__)
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif

    // 无边框窗口：系统标题栏由 MainWindow::DrawTitleBar 自绘
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    // 初始隐藏窗口，避免居中过程中的闪烁
    glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);

    // 创建主窗口（改为 4:3 比例，1200×900）
    GLFWwindow* window = glfwCreateWindow(1200, 900, (const char*)u8"未注册域名扫描工具 v1.0.0", nullptr, nullptr);
    if (window == nullptr)
        return 1;

    // 获取主显示器工作区域，将窗口居中显示
    GLFWmonitor* primary = glfwGetPrimaryMonitor();
    if (primary) {
        int monitorX, monitorY, monitorWidth, monitorHeight;
        glfwGetMonitorWorkarea(primary, &monitorX, &monitorY, &monitorWidth, &monitorHeight);
        int windowWidth, windowHeight;
        glfwGetWindowSize(window, &windowWidth, &windowHeight);
        glfwSetWindowPos(window, monitorX + (monitorWidth - windowWidth) / 2, monitorY + (monitorHeight - windowHeight) / 2);
    }
    glfwShowWindow(window);
    glfwFocusWindow(window);

    // 加载并设置任务栏/窗口图标
    GLFWimage images[1];
    int iconChannels;
    HRSRC hResImg = FindResourceA(NULL, MAKEINTRESOURCEA(103), (LPCSTR)RT_RCDATA);
    if (hResImg) {
        HGLOBAL hData = LoadResource(NULL, hResImg);
        DWORD size = SizeofResource(NULL, hResImg);
        const void* pData = LockResource(hData);
        if (pData) {
            images[0].pixels = stbi_load_from_memory((const stbi_uc*)pData, size, &images[0].width, &images[0].height, &iconChannels, 4);
        } else {
            images[0].pixels = NULL;
        }
    } else {
        images[0].pixels = NULL;
    }
    if (images[0].pixels) {
        glfwSetWindowIcon(window, 1, images);
        stbi_image_free(images[0].pixels);
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // 垂直同步，降低 CPU 占用

    // 初始化 Dear ImGui 上下文
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // 加载中文字体（微软雅黑）；Oversample 设为 1 避免纹理图集过大
    ImFontConfig font_config;
    font_config.OversampleH = 1;
    font_config.OversampleV = 1;
    font_config.PixelSnapH = true;

    // 字形范围：完整中文 + 符号区（★☆、几何图形等），避免 UI 出现方块
    static ImVector<ImWchar> s_glyphRanges;
    {
        ImFontGlyphRangesBuilder builder;
        builder.AddRanges(io.Fonts->GetGlyphRangesChineseFull());
        static const ImWchar kSymbolRanges[] = {
            0x2190, 0x21FF, // 箭头
            0x2460, 0x24FF, // 带圈数字
            0x2500, 0x257F, // 制表符
            0x25A0, 0x25FF, // 几何图形
            0x2600, 0x26FF, // 杂项符号（★ ☆ ⚙ 等）
            0x2700, 0x27BF, // 装饰符号
            0x2B00, 0x2BFF, // 箭头扩展
            0,
        };
        builder.AddRanges(kSymbolRanges);
        builder.BuildRanges(&s_glyphRanges);
    }

    io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\msyh.ttc", 18.0f, &font_config, s_glyphRanges.Data);
    // Fonts[1]：大号 ASCII 数字（圆环评分用），控制纹理体积
    io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\msyh.ttc", 42.0f, &font_config, io.Fonts->GetGlyphRangesDefault());
    // Fonts[2]：面板标题字号 26px
    io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\msyh.ttc", 26.0f, &font_config, s_glyphRanges.Data);

    ImGui::StyleColorsDark();

    // 绑定 GLFW + OpenGL3 渲染后端
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // 后台加载 ECDICT 词典（内存映射，供寓意分析使用）
    // 加载资源字典
    HRSRC hResDict = FindResource(NULL, MAKEINTRESOURCE(102), RT_RCDATA);
    if (hResDict) {
        HGLOBAL hData = LoadResource(NULL, hResDict);
        DWORD size = SizeofResource(NULL, hResDict);
        const char* pData = (const char*)LockResource(hData);
        if (pData && size > 0) {
            Dictionary::InitFromMemory(pData, size);
        }
    }

    // 主循环：事件轮询 → ImGui 帧 → MainWindow 布局 → 清屏 → 呈现
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        MainWindow::Render(window);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.945f, 0.961f, 0.976f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
