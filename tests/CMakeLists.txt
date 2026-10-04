enable_testing()

set(TESTS
    test_smoke
    test_fuzzy
    test_grep
    test_ignore
    test_finder
)

foreach(test_name IN LISTS TESTS)
    add_executable(${test_name} "${test_name}.cpp")
    target_link_libraries(${test_name} PRIVATE brosearch)
    target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
