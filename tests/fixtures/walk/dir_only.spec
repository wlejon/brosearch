# "foo/" matches only directories; "bar" matches files and directories.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = foo/\nbar\n
@file foo/a
@file d/foo
@file bar
@file e/bar/b
@file keep
@expect
.gitignore
d/foo
keep
