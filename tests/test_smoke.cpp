#include "brosearch/search.h"
#include <cassert>
#include <iostream>

#ifdef _WIN32
#include <crtdbg.h>
#include <cstdlib>
#endif

int main() {
#ifdef _WIN32
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif

    std::cout << "[test_smoke] Checking version..." << std::endl;
    assert(bro::search::version_major() == 0);
    assert(bro::search::version_minor() == 1);
    assert(bro::search::version_patch() == 0);
    assert(bro::search::version_string() == "0.1.0");

    std::cout << "[test_smoke] Checking CancellationToken..." << std::endl;
    bro::search::CancellationToken token;
    assert(!token.is_cancelled());
    token.cancel();
    assert(token.is_cancelled());
    token.reset();
    assert(!token.is_cancelled());

    std::cout << "[test_smoke] Checking CancellationSource..." << std::endl;
    bro::search::CancellationSource source;
    auto tok = source.token();
    assert(tok != nullptr);
    assert(!source.is_cancelled());
    assert(!tok->is_cancelled());
    source.cancel();
    assert(source.is_cancelled());
    assert(tok->is_cancelled());
    source.reset();
    assert(!source.is_cancelled());
    assert(!tok->is_cancelled());

    std::cout << "[test_smoke] Smoke tests passed!" << std::endl;
    return 0;
}
