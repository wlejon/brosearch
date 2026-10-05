# core.precomposeUnicode=true (macOS; `git init` writes it there): names stored decomposed (NFD)
# are matched, and listed, composed (NFC). Patterns are used as written, so an NFD pattern no
# longer matches the NFC name it denotes.
@oracle git
@darwin
@options hidden glob=!.git
@git . ignorecase=false precompose=true
@file .gitignore = caf\xc3\xa9.txt\nnai\xcc\x88ve.md\nr\xc3\xa9sum\xc3\xa9/\n
@file cafe\xcc\x81.txt
@file na\xc3\xafve.md
@file re\xcc\x81sume\xcc\x81/cv.txt
@file u\xcc\x88ber.md
@file plain.txt
@expect
.gitignore
na\xc3\xafve.md
plain.txt
\xc3\xbcber.md
