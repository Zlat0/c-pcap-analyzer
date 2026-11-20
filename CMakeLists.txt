cmake_minimum_required(VERSION 3.22)
project(pcapan VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(PA_WERROR "Treat warnings as errors" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(CAIRO REQUIRED cairo)

file(GLOB_RECURSE PA_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.c)

add_executable(pcapan ${PA_SOURCES})
target_include_directories(pcapan PRIVATE ${CMAKE_SOURCE_DIR}/src ${PCAP_INCLUDE_DIRS} ${CAIRO_INCLUDE_DIRS})
target_compile_definitions(pcapan PRIVATE _POSIX_C_SOURCE=200809L)
target_compile_options(pcapan PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
if(PA_WERROR)
    target_compile_options(pcapan PRIVATE -Werror)
endif()
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -fsanitize=address,undefined")
set(CMAKE_C_FLAGS_RELEASE "-O2")
target_link_libraries(pcapan PRIVATE ${PCAP_LIBRARIES} ${CAIRO_LIBRARIES} m)
target_link_directories(pcapan PRIVATE ${PCAP_LIBRARY_DIRS} ${CAIRO_LIBRARY_DIRS})
