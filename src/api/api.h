#pragma once

#include <functional>
#include <string>

namespace brosearch::api {

/// Mounts `bro.search` into the current Bronze realm.
void installSearch();

/// Drains pending async search and grep operations and settles promises/callbacks on the JS thread.
bool tickSearchAsync();

/// Cancels and shuts down any active background search workers.
void shutdownSearchAsync();

// ---- Access -----------------------------------------------------------------------
//
// Which paths a program may read is the host's decision, not brosearch's: every
// native that takes a path asks the host's one access gate,
// bronze::embed::checkAccess (embed/embed_access.h), with AccessKind::Read and
// the path, absolute and lexically normal (UTF-8); the host canonicalizes it
// (symlinks) before deciding, and a directory it allows covers what is inside, so
// a walk asks once for its root, not per file. It is asked on the JS thread that
// made the call, synchronously, before any work is queued. With no gate installed
// every path is allowed and nothing below changes.
//
// What each native asks (all Read; bro.search writes nothing):
//   files, filesSync        the root of the walk
//   grep, grepSync          the root searched (a directory, or the one file)
//   GitignoreMatcher(root)  the root its ignore files are read under
//   GitignoreMatcher.loadFile(path)  the file
//
// A refusal is bronze::embed::newAccessError: an Error whose `message` is the
// gate's sentence (named PermissionRevoked for a grant taken back), `code` is
// "EACCES" and `path` the absolute path asked about: thrown by a synchronous
// native, the promise rejected with it by an asynchronous one.
//
// files() and grep() keep reading after the call returns, so each is held in the
// gate's ledger (holdAccess) on the calling thread until its promise settles.
// When the host changes its grants and the gate refuses the root again, the job
// is cancelled (through its cancellation token), streams no more onFile/onMatch
// calls, and its promise rejects with the refusal at the next tickSearchAsync.

} // namespace brosearch::api

using brosearch::api::installSearch;
using brosearch::api::tickSearchAsync;
using brosearch::api::shutdownSearchAsync;
