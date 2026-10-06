add_library(brosearch_api STATIC
    api.cpp
    host_class.cpp
    native_search_fuzzy.cpp
    native_search_walk.cpp
    native_search_grep.cpp
)

target_include_directories(brosearch_api PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
)

target_link_libraries(brosearch_api PUBLIC
    brosearch
    bronze_runtime_shared
)

target_compile_features(brosearch_api PUBLIC cxx_std_20)
