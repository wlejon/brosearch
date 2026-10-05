# UTF-8 names in paths and patterns.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = caf\xc3\xa9.txt\nna\xc3\xafve/\n\xc3\xbc*\n
@file caf\xc3\xa9.txt
@file cafe.txt
@file na\xc3\xafve/x.txt
@file \xc3\xbcber.md
@file \xe6\x97\xa5\xe6\x9c\xac/\xe8\xaa\x9e.txt
@expect
.gitignore
cafe.txt
\xe6\x97\xa5\xe6\x9c\xac/\xe8\xaa\x9e.txt
