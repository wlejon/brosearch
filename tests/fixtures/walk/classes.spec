# Bracket classes: POSIX [:class:], negation, ranges, escaped brackets, '?'.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = [[:digit:]]*.txt\nfile[!a-c].md\n[[:upper:]][[:lower:]]*.c\n\\[x\\].h\nq?.z\n[^x]y.w\n
@file 1a.txt
@file a1.txt
@file filea.md
@file filed.md
@file Abc.c
@file xbc.c
@file AB.c
@file [x].h
@file x.h
@file q1.z
@file q12.z
@file ay.w
@file xy.w
@expect
.gitignore
AB.c
a1.txt
filea.md
q12.z
x.h
xbc.c
xy.w
