# -g overrides: includes restrict files (directories still descended), "!" excludes, and
# overrides beat ignore files.
@oracle rg
@options case=sensitive glob=*.c glob=!b* glob=!skip/
@git . ignorecase=false
@file .gitignore = ignored.c\n
@file a.c
@file b.c
@file a.h
@file ignored.c
@file sub/c.c
@file sub/b2.c
@file skip/d.c
@file sub/skip/e.c
@expect
a.c
ignored.c
sub/c.c
