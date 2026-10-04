cmake_minimum_required(VERSION 3.24)

project(brosearch VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Respect memory-conscious compile & link job bounds
if(NOT DEFINED BRO_COMPILE_JOBS)
    set(BRO_COMPILE_JOBS 4 CACHE STRING "Maximum parallel compile jobs")
endif()
if(NOT DEFINED BRO_LINK_JOBS)
    set(BRO_LINK_JOBS 2 CACHE STRING "Maximum parallel link jobs")
endif()
set_property(GLOBAL PROPERTY JOB_POOLS compile_job_pool=${BRO_COMPILE_JOBS} link_job_pool=${BRO_LINK_JOBS})
set(CMAKE_JOB_POOL_COMPILE compile_job_pool)
set(CMAKE_JOB_POOL_LINK link_job_pool)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_options(
        $<$<COMPILE_LANGUAGE:CXX>:/MP>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
    )
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

set(BROSEARCH_SOURCES
    src/version.cpp
    src/cancellation_token.cpp
    src/fuzzy.cpp
    src/ignore.cpp
    src/grep.cpp
    src/finder.cpp
)

add_library(brosearch STATIC ${BROSEARCH_SOURCES})
add_library(brosearch::brosearch ALIAS brosearch)

target_include_directories(brosearch
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

option(BROSEARCH_BUILD_TESTS "Build brosearch test suite" ON)
if(BROSEARCH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
