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

// ---- Path gate ------------------------------------------------------------------
//
// Which paths a program may read is the host's decision, not brosearch's: the host
// knows which app is running and what it was granted. With no gate set (the
// default), every path is allowed and nothing below changes.

enum class PathAccess { Read, Write };

/// Answers "" to allow, or the sentence the refusal carries (naming what the app
/// lacks and the path). `path` is absolute and lexically normal (UTF-8); the host
/// canonicalizes it (symlinks) before deciding, and a directory it allows covers
/// what is inside, so a walk asks once for its root, not per file. The gate is
/// called on the JS thread that made the call, synchronously, before any work is
/// queued, so it may block to ask the user; it must be thread-safe (Workers run
/// natives on their own threads).
///
/// What each native asks (all Read; bro.search writes nothing):
///   files, filesSync        the root of the walk
///   grep, grepSync          the root searched (a directory, or the one file)
///   GitignoreMatcher(root)  the root its ignore files are read under
///   GitignoreMatcher.loadFile(path)  the file
///
/// A refusal is an Error whose `message` is exactly the gate's sentence, `code` is
/// "EACCES" and `path` the absolute path asked about: thrown by a synchronous
/// native, the promise rejected with it by an asynchronous one.
using PathGate = std::function<std::string(const std::string& path, PathAccess access)>;

/// Installs `gate` process-wide (an empty function removes it). Safe to call while
/// realms run: calls already inside the old gate finish against it.
void setPathGate(PathGate gate);

} // namespace brosearch::api

using brosearch::api::installSearch;
using brosearch::api::tickSearchAsync;
using brosearch::api::shutdownSearchAsync;
using brosearch::api::setPathGate;
