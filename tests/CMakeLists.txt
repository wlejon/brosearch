# One test binary; each suite is its own ctest entry (`brosearch_tests --suite <name>`).
# Checks are real (CHECK/CHECK_EQ record failures in every build type, never assert()).
file(GLOB BROSEARCH_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
list(FILTER BROSEARCH_TEST_SOURCES EXCLUDE REGEX ".*test_.*api.*")

add_executable(brosearch_tests ${BROSEARCH_TEST_SOURCES})
target_link_libraries(brosearch_tests PRIVATE brosearch)
target_include_directories(brosearch_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_definitions(brosearch_tests PRIVATE
    BROSEARCH_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
if(MSVC)
    target_link_options(brosearch_tests PRIVATE /STACK:8388608)
endif()

set(BROSEARCH_TEST_SUITES
    core
    ignore
    walk
    fuzzy
    fuzzy_index
    regex
    grep
)

foreach(suite IN LISTS BROSEARCH_TEST_SUITES)
    add_test(NAME ${suite} COMMAND brosearch_tests --suite ${suite})
    set_tests_properties(${suite} PROPERTIES TIMEOUT 300)
endforeach()

if(BROSEARCH_ENABLE_API)
    add_executable(brosearch_test_api
        test_search_api.cpp
    )
    target_include_directories(brosearch_test_api PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/api
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${PROJECT_SOURCE_DIR}/src
    )
    target_link_libraries(brosearch_test_api PRIVATE
        brosearch_api
        brosearch
        bronze_runtime_shared
    )
    if(MSVC)
        target_compile_definitions(brosearch_test_api PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE _WIN32_WINNT=0x0A00)
        add_custom_command(TARGET brosearch_test_api POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:bronze_runtime_shared>
                $<TARGET_FILE_DIR:brosearch_test_api>
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_LINKER_FILE:bronze_runtime_shared>
                $<TARGET_FILE_DIR:brosearch_test_api>
        )
    endif()

    if(NOT BRASS_HOST_BACKEND)
        message(STATUS "brosearch: brosearch_test_api not registered (brass has no code generator for this target)")
    else()
        add_test(NAME brosearch_test_api COMMAND brosearch_test_api)
        set_tests_properties(brosearch_test_api PROPERTIES TIMEOUT 60 SKIP_RETURN_CODE 77)

        add_test(NAME brosearch_test_api_gc_stress COMMAND brosearch_test_api)
        set_tests_properties(brosearch_test_api_gc_stress PROPERTIES
            TIMEOUT 60
            SKIP_RETURN_CODE 77
            ENVIRONMENT "BRONZE_GC_STRESS=1;BRONZE_GC_POISON=1"
        )
        if(WIN32)
            set_tests_properties(brosearch_test_api PROPERTIES
                ENVIRONMENT "PATH=$<TARGET_FILE_DIR:bronze_runtime_shared>;$<TARGET_FILE_DIR:brosearch_test_api>;$ENV{PATH}")
            set_property(TEST brosearch_test_api_gc_stress APPEND PROPERTY
                ENVIRONMENT "PATH=$<TARGET_FILE_DIR:bronze_runtime_shared>;$<TARGET_FILE_DIR:brosearch_test_api>;$ENV{PATH}")
        endif()
    endif()
endif()

