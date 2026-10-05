# The ignore crate reads an ignore file line by line as UTF-8 and stops at the first line that is
# not: "b" after the bad line never applies. A BOM and CRLF line ends are accepted.
@oracle rg
@options case=sensitive
@file .ignore = \xef\xbb\xbfa\r\n\xff\xfe\nb\n
@file a
@file b
@file c
@expect
b
c
