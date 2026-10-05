# A nested repository stops the outer .gitignore (but not the outer .ignore).
@oracle rg
@options case=sensitive
@git . ignorecase=false
@git sub ignorecase=false
@file .gitignore = *.log\n
@file .ignore = *.tmp\n
@file a.log
@file e.dat
@file sub/b.log
@file sub/c.tmp
@file sub/.gitignore = *.dat\n
@file sub/d.dat
@file sub/f.txt
@expect
e.dat
sub/b.log
sub/f.txt
