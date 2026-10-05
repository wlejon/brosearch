# --no-ignore-parent: ancestors' ignore files are not read, but the repository is still
# detected through them (so the subdirectory's own .gitignore applies).
@oracle rg
@options case=sensitive no-ignore-parent
@git . ignorecase=false
@root sub
@file .gitignore = *.log\n
@file .ignore = *.tmp\n
@file sub/.gitignore = *.dat\n
@file sub/a.log
@file sub/b.tmp
@file sub/c.txt
@file sub/d.dat
@expect
a.log
b.tmp
c.txt
