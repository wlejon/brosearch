#pragma once
// fzf's --nth / --delimiter (port of fzf v0.74.4 src/tokenizer.go: Tokenize, Transform,
// StripLastDelimiter, and options.go delimiterRegexp): the fields of an item a query matches.
// Every field fzf builds is a contiguous run of the item's characters, so a field is a range of
// rune indices, matched as a standalone text.

#include "brosearch/fuzzy.h"
#include "brosearch/regex.h"
#include "fuzzy/fuzzy_algo.h"

#include <memory>
#include <string_view>
#include <vector>

namespace bro::search::fuzzy_detail {

struct FieldSlice {
    int32_t begin = 0;  // first rune (fzf's prefixLength)
    int32_t n = 0;      // runes
};

class FieldSpec {
public:
    FieldSpec() = default;
    explicit FieldSpec(const FuzzyOptions& options);

    [[nodiscard]] bool active() const noexcept { return !nth_.empty(); }

    // The fields of an item: `text` is its bytes, `chars` its characters, `byte_offsets` the byte
    // offset of each rune (null when the item is ASCII).
    void fields(std::string_view text, const Chars& chars, const uint32_t* byte_offsets,
                std::vector<FieldSlice>& out) const;

private:
    enum class Kind : uint8_t { Awk, Literal, Regex };
    Kind kind_ = Kind::Awk;
    std::vector<FuzzyField> nth_;
    std::vector<uint32_t> literal_;  // runes
    std::shared_ptr<const Regex> regex_;

    void tokenize(std::string_view text, const Chars& chars, const uint32_t* byte_offsets,
                  std::vector<FieldSlice>& tokens) const;
    int32_t strip_last_delimiter(std::string_view text, const Chars& chars, const uint32_t* byte_offsets,
                                 const FieldSlice& f) const;
};

} // namespace bro::search::fuzzy_detail
