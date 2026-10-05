# rg_anchor.spec walked from the subdirectory "sub" (rg run there, no path argument): global and
# --ignore-file patterns now anchor at sub, not at the repository root, so "/ga" hides sub/ga and
# "sub/gb" hides only sub/sub/gb.
@oracle rg
@options case=sensitive ignore-file=../ign/i.txt
@git . ignorecase=false
@root sub
@global = /ga\nsub/gb\ngc/x\n/sub/gd\n
@file ign/i.txt = /ia\nsub/ib\nic/x\n/sub/id\nsub/ie/\n
@file sub/ga
@file sub/gb
@file sub/gc/x
@file sub/gd
@file sub/ia
@file sub/ib
@file sub/ic/x
@file sub/id
@file sub/ie/y
@file sub/sub/ib
@file sub/sub/gb
@expect
gb
gd
ib
id
ie/y
