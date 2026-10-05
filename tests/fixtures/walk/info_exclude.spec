# .git/info/exclude applies below .gitignore in precedence.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@exclude . = *.secret\n!pub.secret\nignored_dir/\n
@file .gitignore = !a.secret\n
@file a.secret
@file b.secret
@file pub.secret
@file sub/c.secret
@file ignored_dir/x
@file normal.txt
@expect
.gitignore
a.secret
normal.txt
pub.secret
