cmake_minimum_required(VERSION 3.20)
project(DomainSniperCpp VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Fetch GLFW
FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG 3.4
)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(glfw)

# Fetch Dear ImGui
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.90.9
)
FetchContent_Populate(imgui)

# Gather ImGui sources
set(IMGUI_DIR ${imgui_SOURCE_DIR})
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

# Application sources
file(GLOB_RECURSE APP_SOURCES 
    "engine/*.cpp"
    "ui/*.cpp"
)

add_executable(${PROJECT_NAME} WIN32 main.cpp app.rc ${APP_SOURCES} ${IMGUI_SOURCES})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    engine
    ui
)

# Link libraries
# OpenGL3 is built-in on Windows (opengl32). We also need Winsock2 (ws2_32) for network.
target_link_libraries(${PROJECT_NAME} PRIVATE
    glfw
    opengl32
    ws2_32
    winhttp
    dwmapi
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(${PROJECT_NAME} PRIVATE -O3 -flto -finput-charset=UTF-8 -fexec-charset=UTF-8)
    target_link_options(${PROJECT_NAME} PRIVATE -O3 -flto -static -static-libgcc -static-libstdc++)
elseif(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()
