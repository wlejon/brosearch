# ripgrep precedence: .rgignore > .ignore > .gitignore, decided per kind before directory depth
# (so a root .ignore rule beats a deeper .gitignore whitelist).
@oracle rg
@options case=sensitive
@git . ignorecase=false
@file .gitignore = a.txt\nb.txt\n
@file .ignore = !a.txt\nc.txt\nd.txt\n
@file .rgignore = !c.txt\nb.txt\n
@file a.txt
@file b.txt
@file c.txt
@file d.txt
@file sub/.gitignore = !d.txt\n
@file sub/d.txt
@file e.txt
@expect
a.txt
c.txt
e.txt
