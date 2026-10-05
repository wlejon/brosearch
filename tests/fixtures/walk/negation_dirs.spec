# Re-including a directory below a "dir/*" rule, and anchored negations.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = dir/*\n!dir/keep/\ndir/keep/*.o\n/*.log\n!important.log\n
@file dir/a
@file dir/keep/b
@file dir/keep/c.o
@file dir/other/d
@file x.log
@file important.log
@file sub/y.log
@expect
.gitignore
dir/keep/b
important.log
sub/y.log
