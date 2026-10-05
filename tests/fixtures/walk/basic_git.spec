# Core gitignore semantics: escapes, negation, anchoring, dir-only, "**", classes, nested files,
# no re-include below an excluded directory.
@oracle git
@options hidden glob=!.git case=auto
@git . ignorecase=false
@file .gitignore = # comment\n\\#hash.txt\n\\!bang.txt\n*.o\n!keep.o\n/rootonly.txt\nbuild/\ndocs/**/*.tmp\n**/logs\nout/**\nexcl/\n!excl/inner.txt\ncls[0-9].dat\nsub/x.txt\n
@file #hash.txt
@file !bang.txt
@file bang.txt
@file a.o
@file keep.o
@file sub/b.o
@file sub/keep.o
@file rootonly.txt
@file sub/rootonly.txt
@file build/x.c
@file sub/build/y.c
@file other/build
@file docs/a.tmp
@file docs/x/y/b.tmp
@file docs/c.txt
@file d2/docs/e.tmp
@file logs/l.txt
@file deep/logs/l.txt
@file out/o.txt
@file out/deeper/p.txt
@file excl/inner.txt
@file cls1.dat
@file clsx.dat
@file sub/x.txt
@file deep/sub/x.txt
@file sub/.gitignore = !b.o\n*.txt\n!keep.txt\n
@file sub/keep.txt
@file sub/c.txt
@file sub/sub2/d.txt
@expect
.gitignore
bang.txt
clsx.dat
d2/docs/e.tmp
deep/sub/x.txt
docs/c.txt
keep.o
other/build
sub/.gitignore
sub/b.o
sub/keep.o
sub/keep.txt
