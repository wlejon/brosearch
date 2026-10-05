# Bracket classes as ripgrep (globset) reads them, against classes.spec's git reading: no POSIX
# "[:digit:]" ('[' and ':' are members, the first ']' closes), a backslash is a member, a '-' after
# a range extends it, a reversed range is an error (line skipped), an unclosed '[' is literal, and
# a class (negated too) matches '/'.
@oracle rg
@options case=sensitive
@file .ignore = [[:digit:]]*.txt\nd[[:alpha:]]x\n[^x]y.w\n[!a]z.w\n[]]b.q\n[a-]c.q\n[\\]]x\n[a-c-e]r\n[z-a]t\n[!]]u\nab[c\n[[]v\n[a]]w\na[!b]c\nd?f\nk[/]l\n
@file 1a.txt
@file g]a.txt
@file ga.txt
@file dax
@file dp]x
@file ay.w
@file xy.w
@file ^y.w
@file az.w
@file bz.w
@file ]b.q
@file -c.q
@file ac.q
@file ]x
@file dr
@file -r
@file er
@file zt
@file ]u
@file qu
@file ab[c
@file abc
@file [v
@file a]w
@file aw
@file a/c
@file d/f
@file k/l
@expect
-r
1a.txt
]u
]x
abc
aw
az.w
d/f
dax
ga.txt
xy.w
zt
