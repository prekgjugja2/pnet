cmake_minimum_required(VERSION 3.16)
project(pnet_engine LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(pnet_scan
    src/pnet_scan.c
    src/main.cpp
)

target_include_directories(pnet_scan PRIVATE include)

if(WIN32)
    target_link_libraries(pnet_scan PRIVATE ws2_32 iphlpapi)
    # ICMP is in iphlpapi on modern Windows
endif()

install(TARGETS pnet_scan RUNTIME DESTINATION bin)
