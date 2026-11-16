// scan.h — pattern-scan fallback untuk libpvz.so (PvZ2), v1.1.
//
// Primary resolution adalah dlsym() nama mangled (stabil selama signature
// C++ tak berubah). Bila dlsym gagal, resolver beralih ke sini, dengan
// urutan: tabel GENERIK dulu (pola yang diharapkan stabil lintas versi),
// lalu tabel per-versi (3180; 3190 ditambahkan begitu dump-nya didapat).
// Tiap pola = 2 jendela byte independen (prologue +0 dan mid-body +0x40)
// di segmen executable libpvz.so. Kedua jendela harus cocok pada jarak
// relatif yang tepat (cross-check); bila tidak ada yang cocok ->
// FAIL-CLOSED (bukan nekat pakai offset lama).
#pragma once

#include <cstdint>
#include <cstring>

#include "patterns_3180.h"
#include "patterns_generic.h"

// Scan [base, base+len) langkah 4 byte (instruksi ARM64 4-byte aligned).
// Kembalikan alamat fungsi, atau nullptr bila tidak cocok.
static inline void* pvz_scan_pattern(uintptr_t base, size_t len,
                                     const PvzPattern& pat) {
    if (len < 0x40 + 16) return nullptr;
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(base);
    for (size_t i = 0; i + 0x40 + 16 <= len; i += 4) {
        if (std::memcmp(mem + i, pat.prologue, 16) == 0 &&
            std::memcmp(mem + i + 0x40, pat.mid, 16) == 0) {
            return reinterpret_cast<void*>(base + i);
        }
    }
    return nullptr;
}

static inline const PvzPattern* pvz_find_in(const char* name,
                                            const PvzPattern* table,
                                            int count) {
    for (int i = 0; i < count; i++) {
        if (std::strcmp(table[i].name, name) == 0) return &table[i];
    }
    return nullptr;
}

// Tabel generik (lapis pertama cadangan).
static inline const PvzPattern* pvz_find_pattern_generic(const char* name) {
    return pvz_find_in(name, kPvzPatternsGeneric, kPvzPatternCountGeneric);
}

// Tabel per-versi 3180 (lapis kedua cadangan).
// TODO(3190): tambah patterns_3190.h + pvz_find_pattern_3190() begitu
// dump libpvz.so 3.19.0 tersedia dari mirror publik.
static inline const PvzPattern* pvz_find_pattern_3180(const char* name) {
    return pvz_find_in(name, kPvzPatterns3180, kPvzPatternCount3180);
}
