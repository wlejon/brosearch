# core.ignorecase=false: same tree as case_insensitive, patterns compared exactly.
@oracle git
@options hidden glob=!.git case=auto
@git . ignorecase=false
@file .gitignore = *.TXT\nBuild/\n/ReadMe.md\n[A-C]*.dat\nsub/Deep/\n
@file a.txt
@file B.Txt
@file build/x
@file sub/BUILD/y
@file readme.md
@file b.dat
@file D.dat
@file sub/deep/z
@file keep.c
@expect
.gitignore
B.Txt
D.dat
a.txt
b.dat
build/x
keep.c
readme.md
sub/BUILD/y
sub/deep/z
