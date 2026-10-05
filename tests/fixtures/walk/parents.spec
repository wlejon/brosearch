# Walking a subdirectory: ignore files of its ancestors apply (up to the repository root for
# .gitignore).
@oracle rg
@options case=sensitive parents
@git . ignorecase=false
@root sub
@file .gitignore = *.log\nsub/anchored.txt\n
@file .ignore = *.tmp\n
@file sub/a.log
@file sub/b.tmp
@file sub/c.txt
@file sub/anchored.txt
@file sub/deeper/anchored.txt
@expect
c.txt
deeper/anchored.txt
