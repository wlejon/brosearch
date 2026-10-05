cmake_minimum_required(VERSION 3.24)

project(brosearch VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:/MP>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>
    )
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)

# Sources are grouped by module directory under src/ (fuzzy, ignore, walk, regex, grep, core).
# Platform-specific translation units guard themselves with #ifdef, so the glob is portable.
file(GLOB_RECURSE BROSEARCH_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(brosearch STATIC ${BROSEARCH_SOURCES})
add_library(brosearch::brosearch ALIAS brosearch)

target_include_directories(brosearch
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(brosearch PUBLIC Threads::Threads)

option(BROSEARCH_BUILD_TESTS "Build the brosearch test suite" ON)
option(BROSEARCH_BUILD_TOOLS "Build the brosearch CLI (differential-oracle driver)" ON)

if(BROSEARCH_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(BROSEARCH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
