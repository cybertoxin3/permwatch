// ES'ye bağımlı olmayan JSON yardımcıları (unit test edilebilsin diye ayrı).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Geçerli bir UTF-8 dizisinin byte uzunluğunu döndürür; geçersizse 0.
size_t utf8_seq_len(const unsigned char *s, size_t rem);

// JSON string yazar. Kontrol karakterleri escape edilir,
// geçersiz UTF-8 byte'ları � olarak yazılır.
void json_str_n(FILE *f, const char *s, size_t n);

// Byte dizisini küçük harf hex string olarak yazar.
void json_hex(FILE *f, const uint8_t *b, size_t n);
