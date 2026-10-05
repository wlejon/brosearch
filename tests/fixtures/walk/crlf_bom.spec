# CRLF line endings and a UTF-8 BOM in .gitignore.
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@file .gitignore = \xef\xbb\xbf*.log\r\n!keep.log\r\n/dir/\r\n\r\n# c\r\nlast.txt
@file a.log
@file keep.log
@file dir/x
@file sub/dir/y
@file last.txt
@file other.txt
@expect
.gitignore
keep.log
other.txt
sub/dir/y
