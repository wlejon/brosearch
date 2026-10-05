# Hidden entries are skipped unless an ignore rule whitelists them.
@oracle rg
@options case=sensitive
@git . ignorecase=false
@file .gitignore = !.env\n!.shown/\n
@file .env
@file .hidden
@file .dir/x
@file .shown/y
@file vis.txt
@file sub/.inner
@expect
.env
.shown/y
vis.txt
