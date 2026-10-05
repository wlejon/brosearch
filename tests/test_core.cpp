#include "harness.h"

#include "brosearch/cancellation_token.h"
#include "brosearch/version.h"

#include <thread>

using namespace bro::search;

TEST(core, version) {
    CHECK_EQ(version_string(), std::string_view(BROSEARCH_VERSION_STRING));
    CHECK_EQ(version_major(), static_cast<uint32_t>(BROSEARCH_VERSION_MAJOR));
}

TEST(core, cancellation) {
    CancellationSource src;
    auto tok = src.token();
    CHECK(!tok->is_cancelled());
    std::thread t([&] { src.cancel(); });
    t.join();
    CHECK(tok->is_cancelled());
    CHECK(src.is_cancelled());
    src.reset();
    CHECK(!tok->is_cancelled());
}
