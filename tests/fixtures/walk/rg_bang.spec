# A lone "!" line: git ignores it; the ignore crate turns it into a whitelist of everything (the
# glob "**/"), which also lifts hidden-file skipping.
@oracle rg
@options case=sensitive
@file .ignore = *.a\n!\n
@file x.a
@file y.b
@expect
.ignore
x.a
y.b
