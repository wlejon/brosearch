# Names that are not valid UTF-8 are matched and reported as raw bytes. Oracle is git: rg reads
# ignore files as UTF-8 (lossily), so it cannot express a pattern containing a raw 0xFF byte.
@oracle git
@posix
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = *\xfe*/\nbad\xff.log\n
@file \xffname.txt
@file ok.txt
@file d\xfe/x
@file bad\xff.log
@file bad\xfe.log
@expect
.gitignore
bad\xfe.log
ok.txt
\xffname.txt
