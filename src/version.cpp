#include "brosearch/version.h"

namespace bro::search {

uint32_t version_major() noexcept {
    return BROSEARCH_VERSION_MAJOR;
}

uint32_t version_minor() noexcept {
    return BROSEARCH_VERSION_MINOR;
}

uint32_t version_patch() noexcept {
    return BROSEARCH_VERSION_PATCH;
}

std::string_view version_string() noexcept {
    return BROSEARCH_VERSION_STRING;
}

} // namespace bro::search
