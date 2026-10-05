# Without -L, symbolic links are neither listed nor descended.
@oracle rg
@posix
@options case=sensitive
@file real/a.txt
@symlink link = real
@symlink file.lnk = real/a.txt
@expect
real/a.txt
