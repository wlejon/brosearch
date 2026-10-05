# Outside a git repository .gitignore is not applied (require_git); .ignore still is.
@oracle rg
@options case=sensitive
@file .gitignore = *.a\n
@file .ignore = *.b\n
@file x.a
@file x.b
@file x.c
@expect
x.a
x.c
