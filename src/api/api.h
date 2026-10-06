#pragma once

namespace brosearch::api {

/// Mounts `bro.search` into the current Bronze realm.
void installSearch();

/// Drains pending async search and grep operations and settles promises/callbacks on the JS thread.
bool tickSearchAsync();

/// Cancels and shuts down any active background search workers.
void shutdownSearchAsync();

} // namespace brosearch::api

using brosearch::api::installSearch;
using brosearch::api::tickSearchAsync;
using brosearch::api::shutdownSearchAsync;
