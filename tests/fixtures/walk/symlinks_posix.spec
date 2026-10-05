# -L: links report their target's type, linked directories are walked, loops are cut.
@oracle rg
@posix
@options case=sensitive follow
@file real/a.txt
@symlink link = real
@symlink file.lnk = real/a.txt
@symlink real/up = ..
@symlink broken = nowhere
@expect
file.lnk
link/a.txt
real/a.txt
