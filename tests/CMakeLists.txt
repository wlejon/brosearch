# One test binary; each suite is its own ctest entry (`brosearch_tests --suite <name>`).
# Checks are real (CHECK/CHECK_EQ record failures in every build type, never assert()).
file(GLOB BROSEARCH_TEST_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

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
