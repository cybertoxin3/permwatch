// JSON escape unit testleri. Çalıştır: make test
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/json.h"

static int g_fail = 0;

static void check(const char *name, const char *in, size_t n, const char *want) {
    char *buf = NULL;
    size_t sz = 0;
    FILE *f = open_memstream(&buf, &sz);
    json_str_n(f, in, n);
    fclose(f);
    if (strcmp(buf, want) != 0) {
        printf("FAIL %-28s got %s  want %s\n", name, buf, want);
        g_fail++;
    } else {
        printf("ok   %s\n", name);
    }
    free(buf);
}
#define CHECK(name, lit, want) check(name, lit, sizeof(lit) - 1, want)

int main(void) {
    CHECK("ascii",              "/usr/bin/curl",      "\"/usr/bin/curl\"");
    CHECK("tirnak ve ters bolu", "a\"b\\c",           "\"a\\\"b\\\\c\"");
    CHECK("satir sonu ve tab",  "a\nb\tc\r",          "\"a\\nb\\tc\\r\"");
    CHECK("kontrol karakteri",  "a\x01" "b\x7f",      "\"a\\u0001b\\u007f\"");
    CHECK("gecerli utf8 (tr)",  "Çalıştır",           "\"Çalıştır\"");
    CHECK("gecerli 4 byte",     "\xF0\x9F\x94\x92",   "\"\xF0\x9F\x94\x92\"");
    CHECK("gecersiz tek byte",  "a\xFF" "b",          "\"a\\ufffdb\"");
    CHECK("yarim dizi (sonda)", "a\xC3",              "\"a\\ufffd\"");
    CHECK("overlong '/'",       "\xC0\xAF",           "\"\\ufffd\\ufffd\"");
    CHECK("surrogate",          "\xED\xA0\x80",       "\"\\ufffd\\ufffd\\ufffd\"");
    CHECK("gomulu NUL",         "a\0b",               "\"a\\u0000b\"");

    printf("\n%s (%d hata)\n", g_fail ? "BASARISIZ" : "TAMAM", g_fail);
    return g_fail ? 1 : 0;
}
