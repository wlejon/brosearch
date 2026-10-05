# core.precomposeUnicode=false: names are the bytes on disk, so NFC patterns miss NFD names.
@oracle git
@darwin
@options hidden glob=!.git
@git . ignorecase=false precompose=false
@file .gitignore = caf\xc3\xa9.txt\nnai\xcc\x88ve.md\nr\xc3\xa9sum\xc3\xa9/\n
@file cafe\xcc\x81.txt
@file na\xc3\xafve.md
@file re\xcc\x81sume\xcc\x81/cv.txt
@file u\xcc\x88ber.md
@file plain.txt
@expect
.gitignore
cafe\xcc\x81.txt
na\xc3\xafve.md
plain.txt
re\xcc\x81sume\xcc\x81/cv.txt
u\xcc\x88ber.md
