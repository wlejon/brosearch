#pragma once

#include <cstdint>
#include <string_view>

#define BROSEARCH_VERSION_MAJOR 0
#define BROSEARCH_VERSION_MINOR 2
#define BROSEARCH_VERSION_PATCH 0
#define BROSEARCH_VERSION_STRING "0.2.0"

namespace bro::search {

uint32_t version_major() noexcept;
uint32_t version_minor() noexcept;
uint32_t version_patch() noexcept;
std::string_view version_string() noexcept;

} // namespace bro::search
