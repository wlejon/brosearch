# Rules in a subdirectory's .gitignore anchor to that subdirectory.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file sub/.gitignore = /x\ny/z\n*.q\n
@file sub/x
@file sub/d/x
@file x
@file sub/y/z
@file sub/d/y/z
@file y/z
@file sub/a.q
@file b.q
@expect
b.q
sub/.gitignore
sub/d/x
sub/d/y/z
x
y/z
