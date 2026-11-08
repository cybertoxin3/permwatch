#!/bin/zsh
# libyara'yı statik kütüphane olarak derler: build_libyara.sh <yara-kaynak> <çıktı-klasörü> <arch>
set -euo pipefail
Y=$1; OUT=$2; ARCH=${3:-$(uname -m)}
SRC=(ahocorasick arena atoms base64 bitmask compiler endian exec exefiles filemap hash libyara mem modules notebook
     object parser proc re rules scan scanner simple_str sizedstr stack stopwatch strutils stream threading
     grammar lexer hex_grammar hex_lexer re_grammar re_lexer tlshc/tlsh tlshc/tlsh_impl tlshc/tlsh_util proc/mach
     modules/tests/tests modules/elf/elf modules/math/math modules/time/time modules/pe/pe modules/pe/pe_utils
     modules/console/console modules/string/string modules/hash/hash modules/macho/macho)
mkdir -p "$OUT/obj"
for f in $SRC; do
    cc -c -O2 -arch $ARCH -mmacosx-version-min=14.0 -w -I"$Y/libyara/include" -I"$Y/libyara" \
       -DHASH_MODULE -DMACHO_MODULE -DHAVE_COMMONCRYPTO_COMMONCRYPTO_H -DUSE_MACH_PROC -DNDEBUG=1 \
       -DBUCKETS_128=1 -DCHECKSUM_1B=1 "$Y/libyara/$f.c" -o "$OUT/obj/${f//\//_}.o"
done
rm -f "$OUT/libyara.a"
ar rcs "$OUT/libyara.a" "$OUT"/obj/*.o
