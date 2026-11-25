cmake_minimum_required(VERSION 3.15)
project(ProxyServerWindowsTests LANGUAGES CXX)
if(NOT WIN32)
  message(FATAL_ERROR "These targets are for Windows. The SCM integration also requires a disposable GitHub-hosted runner.")
endif()
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
get_filename_component(PROXY_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
find_package(Threads REQUIRED)
add_executable(service_integration_win
  ../service_integration_win.cpp
  ${PROXY_ROOT}/src/service_host_win.cpp
  ${PROXY_ROOT}/src/service_codec.cpp
  ${PROXY_ROOT}/src/service_firewall_plan.cpp
  ${PROXY_ROOT}/src/service_firewall_win.cpp
  ${PROXY_ROOT}/src/gost_config.cpp
  ${PROXY_ROOT}/src/proxy_backend_win.cpp
  ${PROXY_ROOT}/src/child_process_win.cpp
  ${PROXY_ROOT}/src/mtproto_win.cpp)
target_include_directories(service_integration_win PRIVATE ${PROXY_ROOT}/src)
target_compile_definitions(service_integration_win PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(service_integration_win PRIVATE Threads::Threads ws2_32 crypt32 advapi32 user32 shell32 bcrypt winhttp ole32 oleaut32 uuid gdi32 gdiplus)
if(MSVC)
  target_compile_options(service_integration_win PRIVATE /W4 /utf-8)
elseif(MINGW)
  target_link_options(service_integration_win PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()
add_custom_command(TARGET service_integration_win POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${PROXY_ROOT}/components" "$<TARGET_FILE_DIR:service_integration_win>/components")
enable_testing()
add_executable(service_firewall_tests ../test_service_firewall.cpp ${PROXY_ROOT}/src/service_firewall_plan.cpp)
target_include_directories(service_firewall_tests PRIVATE ${PROXY_ROOT}/src)
add_test(NAME firewall_plan COMMAND service_firewall_tests)
add_executable(service_codec_tests ../test_service_codec.cpp ${PROXY_ROOT}/src/service_codec.cpp)
target_include_directories(service_codec_tests PRIVATE ${PROXY_ROOT}/src)
add_test(NAME service_codec COMMAND service_codec_tests)
