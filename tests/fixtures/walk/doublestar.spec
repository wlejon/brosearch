# "**" rules: leading "**/", trailing "/**", "a/**/b", and "**" that is not a whole component.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = **/foo\nabc/**\na/**/b\n**/x/**/y.txt\nfoo**bar\nm*/n\n
@file foo
@file d/foo
@file abc/1
@file abc/d/2
@file zz/abc
@file a/b
@file a/x/b
@file a/x/y/b
@file a/bb
@file x/y.txt
@file q/x/r/s/y.txt
@file q/y.txt
@file fooXbar
@file foo2/bar
@file mm/n
@file m/q/n
@expect
.gitignore
a/bb
foo2/bar
m/q/n
q/y.txt
zz/abc
