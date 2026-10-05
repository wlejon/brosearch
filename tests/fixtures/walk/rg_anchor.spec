# How ripgrep anchors global excludes and --ignore-file patterns: against the path it prints,
# here relative to the walk root "." (the ignore file's own directory does not matter).
# global.spec has git's reading (relative to the repository root).
@oracle rg
@options case=sensitive ignore-file=ign/i.txt
@git . ignorecase=false
@global = /ga\nsub/gb\ngc/x\n/sub/gd\n
@file ign/i.txt = /ia\nsub/ib\nic/x\n/sub/id\nsub/ie/\n
@file ga
@file gb
@file gc/x
@file sub/ga
@file sub/gb
@file sub/gc/x
@file sub/gd
@file ia
@file ib
@file ic/x
@file sub/ia
@file sub/ib
@file sub/ic/x
@file sub/id
@file sub/ie/y
@file sub/sub/ib
@file sub/sub/gb
@file ign/ia
@file ign/sub/ib
@expect
gb
ib
ign/i.txt
ign/ia
ign/sub/ib
sub/ga
sub/gc/x
sub/ia
sub/ic/x
sub/sub/gb
sub/sub/ib
