cmake_minimum_required(VERSION 3.24)

project(brosearch VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Coverage. Scoped to a top-level build: a consumer that add_subdirectory()s
# brosearch has no business having its own build instrumented from in here.
option(BROSEARCH_COVERAGE "Instrument the build for gcov coverage (GCC/Clang)" OFF)
if(BROSEARCH_COVERAGE AND PROJECT_IS_TOP_LEVEL)
    if(MSVC)
        message(FATAL_ERROR "BROSEARCH_COVERAGE requires GCC or Clang (gcov instrumentation)")
    endif()
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

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
if(APPLE)
    # git's NFD -> NFC precomposition (src/ignore/precompose.cpp) goes through the system iconv,
    # the only one with Apple's "UTF-8-MAC" decomposition.
    target_link_libraries(brosearch PRIVATE iconv)
endif()

option(BROSEARCH_BUILD_TESTS "Build the brosearch test suite" ON)
option(BROSEARCH_BUILD_TOOLS "Build the brosearch CLI (differential-oracle driver)" ON)

if(BROSEARCH_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(BROSEARCH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
