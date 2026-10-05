# brosearch CLI: rg/fzf-compatible output so the differential scripts can diff it against the
# real tools (scripts/differential.sh). Subcommands live in cli_<name>.cpp.
add_executable(brosearch-cli
    cli_main.cpp
    cli_grep.cpp
    cli_files.cpp
    cli_fuzzy.cpp
)
target_link_libraries(brosearch-cli PRIVATE brosearch)
target_include_directories(brosearch-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

# Regenerates src/regex/unicode_tables*.inc from the Unicode Character Database.
# Not part of the default build: see the header comment of gen_unicode.cpp.
add_executable(gen_unicode EXCLUDE_FROM_ALL gen_unicode.cpp)

# Regenerates src/fuzzy/fuzzy_unicode_tables.inc (see gen_fuzzy_unicode.cpp).
add_executable(gen_fuzzy_unicode EXCLUDE_FROM_ALL gen_fuzzy_unicode.cpp)
