# Unreadable directories (mode 000): rg reports each ("./locked: Permission denied (os error 13)"),
# exits 2 and lists everything else. One that an ignore rule skips is never opened, so never
# reported. POSIX only; skipped where permissions are not enforced (root).
@oracle rg
@options case=sensitive
@file .ignore = skipped/\n
@file a.txt
@file locked/inner/x.txt
@file ok/b.txt
@file ok/deep/c.txt
@file skipped/z.txt
@unreadable locked
@unreadable ok/deep
@unreadable skipped = pruned
@expect
a.txt
ok/b.txt
