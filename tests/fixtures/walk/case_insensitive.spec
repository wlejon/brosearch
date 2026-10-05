# core.ignorecase=true: ASCII case folding of patterns (CaseMode::Auto reads it from .git/config).
@oracle git
@options hidden glob=!.git case=auto
@git . ignorecase=true
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
D.dat
keep.c
