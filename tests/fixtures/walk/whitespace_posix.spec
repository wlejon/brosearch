# Trailing spaces are trimmed unless escaped; tabs are kept (git semantics). POSIX only:
# Windows cannot create names ending in a space.
@oracle git
@posix
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = trail  \nesc\\ \ntab\t\n
@file trail
@file trail\x20\x20
@file esc
@file esc\x20
@file tab
@file tab\t
@expect
.gitignore
esc
tab
trail\x20\x20
