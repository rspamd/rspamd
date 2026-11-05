#!/usr/bin/env python3
"""
Generates src/libutil/cxx/smtputf8_data.hxx, the code point table for
draft-ietf-mailmaint-smtputf8-syntax.

The table gives the script of each code point the PRECIS IdentifierClass
permits (RFC8264 8, with the exceptions from RFC5892 2.6), and "none" for
the rest. Rule 2 of the draft needs the former and rule 3 the latter.

CONTEXTJ and CONTEXTO code points get their script like any permitted
code point. RFC5892 enumerates them, so smtputf8_syntax.cxx applies their
rules by code point, and this script stops if Unicode ever adds a join
control that the C++ code would not know about.

To move to a new Unicode version, fetch these files from
https://www.unicode.org/Public/<version>/ucd/ into one directory:

  UnicodeData.txt DerivedCoreProperties.txt DerivedNormalizationProps.txt
  Scripts.txt HangulSyllableType.txt PropList.txt

Run:  python3 gen_smtputf8_data.py <dir> > src/libutil/cxx/smtputf8_data.hxx
"""

import os
import re
import sys

MAX_CP = 0x10FFFF

# RFC5892 2.6
EXCEPTIONS = {
    0x00DF: "pvalid", 0x03C2: "pvalid", 0x06FD: "pvalid", 0x06FE: "pvalid",
    0x0F0B: "pvalid", 0x3007: "pvalid",
    0x00B7: "contexto", 0x0375: "contexto", 0x05F3: "contexto",
    0x05F4: "contexto", 0x30FB: "contexto",
    **{cp: "contexto" for cp in range(0x0660, 0x066A)},
    **{cp: "contexto" for cp in range(0x06F0, 0x06FA)},
    0x0640: "disallowed", 0x07FA: "disallowed", 0x302E: "disallowed",
    0x302F: "disallowed", 0x3031: "disallowed", 0x3032: "disallowed",
    0x3033: "disallowed", 0x3034: "disallowed", 0x3035: "disallowed",
    0x303B: "disallowed",
}

# smtputf8_syntax.cxx applies RFC5892 A.1 and A.2 to these and no others
JOIN_CONTROLS = {0x200C, 0x200D}

# smtputf8_syntax.cxx refers to these by name
SCRIPTS_USED_BY_CODE = {"Common", "Inherited", "Greek", "Hebrew", "Han",
                        "Hiragana", "Katakana", "Hangul", "Bopomofo"}

LETTER_DIGITS = {"Ll", "Lu", "Lo", "Nd", "Lm", "Mn", "Mc"}


def ucd_lines(directory, name):
    with open(os.path.join(directory, name), encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                yield [field.strip() for field in line.split(";")]


def ucd_ranges(directory, name):
    """(first, last, fields after the first) for each line of a UCD file"""
    for fields in ucd_lines(directory, name):
        first, _, last = fields[0].partition("..")
        yield int(first, 16), int(last or first, 16), fields[1:]


def ucd_version(directory):
    with open(os.path.join(directory, "Scripts.txt"), encoding="utf-8") as f:
        m = re.match(r"# Scripts-(\d+\.\d+\.\d+)\.txt", f.readline())
    if not m:
        sys.exit("Scripts.txt does not name its Unicode version")
    return m.group(1)


def categories(directory):
    result = ["Cn"] * (MAX_CP + 1)
    first = None
    for fields in ucd_lines(directory, "UnicodeData.txt"):
        cp, name, category = int(fields[0], 16), fields[1], fields[2]
        if name.endswith(", First>"):
            first = cp
        elif name.endswith(", Last>"):
            result[first:cp + 1] = [category] * (cp + 1 - first)
        else:
            result[cp] = category
    return result


def property_set(directory, name, prop, value=None):
    result = set()
    for first, last, fields in ucd_ranges(directory, name):
        if fields[0] == prop and (value is None or fields[1] == value):
            result.update(range(first, last + 1))
    return result


def property_map(directory, name):
    result = {}
    for first, last, fields in ucd_ranges(directory, name):
        for cp in range(first, last + 1):
            result[cp] = fields[0]
    return result


def identifier_class(cp, category, props):
    """The RFC8264 8 algorithm, in its order, for the IdentifierClass"""
    if cp in EXCEPTIONS:
        return EXCEPTIONS[cp]
    if category == "Cn" and cp not in props["noncharacters"]:
        return "unassigned"
    if 0x21 <= cp <= 0x7E:
        return "pvalid"
    if cp in props["join_controls"]:
        return "contextj"
    if props["hangul"].get(cp) in ("L", "V", "T"):
        return "disallowed"
    if cp in props["ignorable"] or cp in props["noncharacters"]:
        return "disallowed"
    if category == "Cc":
        return "disallowed"
    if cp in props["has_compat"]:
        return "disallowed"
    if category in LETTER_DIGITS:
        return "pvalid"
    # OtherLetterDigits, Spaces, Symbols and Punctuation are ID_DIS
    return "disallowed"


def enum_name(script):
    return script.lower()


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: gen_smtputf8_data.py <directory with UCD files>")
    directory = sys.argv[1]
    version = ucd_version(directory)

    props = {
        "noncharacters": property_set(directory, "PropList.txt",
                                      "Noncharacter_Code_Point"),
        "join_controls": property_set(directory, "PropList.txt",
                                      "Join_Control"),
        "ignorable": property_set(directory, "DerivedCoreProperties.txt",
                                  "Default_Ignorable_Code_Point"),
        "has_compat": property_set(directory, "DerivedNormalizationProps.txt",
                                   "NFKC_QC", "N"),
        "hangul": property_map(directory, "HangulSyllableType.txt"),
    }

    if props["join_controls"] != JOIN_CONTROLS:
        sys.exit("Join_Control is now %s; smtputf8_syntax.cxx needs a rule "
                 "for each" % sorted(hex(cp) for cp in props["join_controls"]))

    scripts = property_map(directory, "Scripts.txt")
    missing = SCRIPTS_USED_BY_CODE - set(scripts.values())
    if missing:
        sys.exit("Scripts.txt lacks %s" % sorted(missing))

    category = categories(directory)
    values = []
    for cp in range(MAX_CP + 1):
        cls = identifier_class(cp, category[cp], props)
        if cls in ("pvalid", "contextj", "contexto"):
            values.append(scripts.get(cp, "Unknown"))
        else:
            values.append(None)

    # "Unknown" can only reach the table if a permitted code point lacks a
    # script, which would be a UCD error
    if "Unknown" in values:
        sys.exit("a permitted code point has no script")

    names = ["none"] + sorted({enum_name(v) for v in values if v})

    ranges = []
    for cp, value in enumerate(values):
        name = enum_name(value) if value else "none"
        if not ranges or ranges[-1][1] != name:
            ranges.append((cp, name))

    print("/*")
    print(" * Generated by utils/gen_smtputf8_data.py from the Unicode %s"
          % version)
    print(" * character database -- do not edit by hand.")
    print(" *")
    print(" * The script of each code point the PRECIS IdentifierClass permits,")
    print(" * and none for the rest.")
    print(" */")
    print()
    print("#ifndef RSPAMD_SMTPUTF8_DATA_HXX")
    print("#define RSPAMD_SMTPUTF8_DATA_HXX")
    print()
    print("#include <cstdint>")
    print()
    print("namespace rspamd::smtputf8 {")
    print()
    print('constexpr const char *unicode_version = "%s";' % version)
    print()
    print("enum class script : std::uint8_t {")
    for name in names:
        print("\t%s," % name)
    print("};")
    print()
    print("/*")
    print(" * Each entry is the first code point of a range, shifted left by")
    print(" * eight, plus the script of the range. A range ends where the next")
    print(" * one starts, and the entries are sorted for binary search.")
    print(" */")
    print("constexpr std::uint32_t range(char32_t first, script s)")
    print("{")
    print("\treturn (static_cast<std::uint32_t>(first) << 8) | static_cast<std::uint8_t>(s);")
    print("}")
    print()
    print("constexpr std::uint32_t script_ranges[] = {")
    for cp, name in ranges:
        print("\trange(0x%04X, script::%s)," % (cp, name))
    print("};")
    print()
    print("}// namespace rspamd::smtputf8")
    print()
    print("#endif")


if __name__ == "__main__":
    main()
