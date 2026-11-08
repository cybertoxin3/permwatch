"""app/i18n/<dil>.tsv dosyalarını <bundle>/Contents/Resources/<lproj>/Localizable.strings'e çevirir.

Her dilin anahtar seti en.tsv ile birebir aynı olmalı ve her çevirideki
format yer tutucuları (%@, %1$@, %ld) İngilizcesiyle eşleşmeli.
"""
import os
import re
import sys

LPROJ = {"en": "en", "tr": "tr", "ru": "ru", "de": "de", "fr": "fr", "es": "es", "pt": "pt", "it": "it",
         "uk": "uk", "ja": "ja", "zh": "zh-Hans", "ko": "ko", "ar": "ar"}
SPEC = re.compile(r"%(?:\d+\$)?(?:@|ld|d)")


def load(path):
    out = {}
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.rstrip("\n")
        if not line:
            continue
        k, sep, v = line.partition("\t")
        if not sep or not v:
            sys.exit(f"{path}:{n}: anahtar<TAB>değer bekleniyordu")
        if k in out:
            sys.exit(f"{path}:{n}: {k} iki kez tanımlı")
        out[k] = v
    return out


def norm(specs):
    # %@ ile %1$@ aynı sayılır; sıra serbest (diller kelime sırasını değiştirebilir).
    return sorted(re.sub(r"\d+\$", "", s) for s in specs)


def esc(s):
    # "\n" (ters bölü + n) satır sonu olarak korunur; diğer ters bölüler kaçışlanır.
    return s.replace("\\n", "\0").replace("\\", "\\\\").replace("\0", "\\n").replace('"', '\\"')


def main(src_dir, res_dir):
    base = load(os.path.join(src_dir, "en.tsv"))
    errors = []
    for code, lproj in LPROJ.items():
        path = os.path.join(src_dir, f"{code}.tsv")
        if not os.path.exists(path):
            if os.environ.get("PARTIAL"):
                continue
            errors.append(f"{code}: dosya yok")
            continue
        t = load(path)
        missing, extra = base.keys() - t.keys(), t.keys() - base.keys()
        if missing or extra:
            errors.append(f"{code}: eksik {sorted(missing)} fazla {sorted(extra)}")
        for k in base.keys() & t.keys():
            if norm(SPEC.findall(base[k])) != norm(SPEC.findall(t[k])):
                errors.append(f"{code}: {k} yer tutucuları uyuşmuyor: {t[k]!r}")
        d = os.path.join(res_dir, f"{lproj}.lproj")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "Localizable.strings"), "w", encoding="utf-8") as f:
            for k in sorted(t):
                f.write(f'"{esc(k)}" = "{esc(t[k])}";\n')
    if errors:
        sys.exit("\n".join(errors))
    print(f"{len(LPROJ)} dil, {len(base)} anahtar")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
