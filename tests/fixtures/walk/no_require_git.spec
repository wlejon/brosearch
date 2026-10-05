# --no-require-git: .gitignore applies without a repository.
@oracle rg
@options case=sensitive no-require-git
@file .gitignore = *.a\n
@file .ignore = *.b\n
@file x.a
@file x.b
@file x.c
@expect
x.c
