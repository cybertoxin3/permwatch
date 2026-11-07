#include "json.h"

size_t utf8_seq_len(const unsigned char *s, size_t rem) {
    unsigned char c = s[0];
    size_t n;
    uint32_t cp;
    if (c < 0x80) return 1;
    else if ((c & 0xE0) == 0xC0) { n = 2; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { n = 3; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { n = 4; cp = c & 0x07; }
    else return 0;
    if (rem < n) return 0;
    for (size_t i = 1; i < n; i++) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    // overlong kodlama, surrogate ve aralık dışı kod noktalarını reddet
    if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) ||
        cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
        return 0;
    return n;
}

void json_str_n(FILE *f, const char *str, size_t len) {
    const unsigned char *s = (const unsigned char *)str;
    fputc('"', f);
    size_t i = 0;
    while (s && i < len) {
        unsigned char c = s[i];
        if (c >= 0x80) {
            size_t n = utf8_seq_len(s + i, len - i);
            if (n == 0) {
                fputs("\\ufffd", f);
                i++;
            } else {
                fwrite(s + i, 1, n, f);
                i += n;
            }
            continue;
        }
        switch (c) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (c < 0x20 || c == 0x7F) fprintf(f, "\\u%04x", c);
                else fputc(c, f);
        }
        i++;
    }
    fputc('"', f);
}

void json_hex(FILE *f, const uint8_t *b, size_t n) {
    fputc('"', f);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fputc('"', f);
}
