# Global excludes (HOME/.config/git/ignore) apply below .gitignore and info/exclude. The
# "\s" escape is a literal 's' (seen in a real global ignore file written with a backslash).
@oracle git
@options hidden glob=!.git
@git . ignorecase=false
@global = *.swp\n!keep.swp\n**/.claude\\settings.local.json\n
@file .gitignore = keep.swp\n
@file a.swp
@file keep.swp
@file sub/b.swp
@file .claude/settings.local.json
@file .claudesettings.local.json
@file x.txt
@expect
.claude/settings.local.json
.gitignore
x.txt
