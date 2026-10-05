# --max-depth 2: entries at depth <= 2 only.
@oracle rg
@options case=sensitive max-depth=2
@file a
@file d1/b
@file d1/d2/c
@file d1/d2/d3/e
@expect
a
d1/b
