# ripgrep's ignore crate trims all trailing whitespace (tabs, Unicode spaces) unless the line ends
# in "\ "; git trims only spaces (see whitespace_posix.spec). A line ending in an escaped space
# keeps it; "esc2\ <tab>" trims to a dangling backslash, which rg reports and skips.
@oracle rg
@options case=sensitive
@file .ignore = tab\t\nsp \t \nnbsp\xc2\xa0\nideo\xe3\x80\x80\nesc\\ \nesc2\\ \t\n  lead\n
@file tab
@file sp
@file nbsp
@file ideo
@file esc
@file esc2
@file lead
@file \x20\x20lead
@expect
esc
esc2
lead
