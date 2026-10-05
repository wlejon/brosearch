# globset's "{a,b}" alternation in ignore files (git has none): nestable, empty alternatives
# dropped ("k{,1}m" is only "k1m", "f{}g" is "fg"), an unclosed '{' or unopened '}' is an error
# (line skipped; so is "\{w}", whose escaped '{' leaves the '}' unopened), "**" inside a group,
# and a '/' inside a group anchors the pattern.
@oracle rg
@options case=sensitive
@file .ignore = {p,q}z\nk{,1}m\nn{a,b\no}r\na{b,{c,d}}e\nf{}g\nh{,}i\n{**/s,l}\nm{n,o/**}\ng{h/i,j}\n\\{w}\n
@file pz
@file qz
@file {p,q}z
@file km
@file k1m
@file n{a,b
@file o}r
@file abe
@file ace
@file ade
@file fg
@file f{}g
@file hi
@file x/s
@file l
@file mn
@file x/mn
@file mo/x/y
@file gj
@file x/gj
@file gh/i
@file {w}
@file w
@expect
f{}g
km
n{a,b
o}r
w
x/gj
x/mn
{p,q}z
{w}
