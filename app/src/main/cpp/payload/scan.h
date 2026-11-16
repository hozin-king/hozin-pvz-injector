// scan.h — pattern-scan fallback untuk libpvz.so (PvZ2).
//
// Primary resolution adalah dlsym() nama mangled (stabil selama signature
// C++ tak berubah). Bila EA men-strip .dynsym di update berikut, dlsym
// gagal dan resolver beralih ke sini: cari 2 jendela byte independen
// (prologue +0 dan mid-body +0x40) di segmen executable libpvz.so.
// Kedua jendela harus cocok pada jarak relatif yang tepat (cross-check);
// bila tidak ada yang cocok -> FAIL-CLOSED (bukan nekat pakai offset lama).
#pragma once

#include <cstdint>
#include <cstring>

#include "patterns_3180.h"

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

static inline const PvzPattern* pvz_find_pattern(const char* name) {
    for (int i = 0; i < kPvzPatternCount3180; i++) {
        if (std::strcmp(kPvzPatterns3180[i].name, name) == 0)
            return &kPvzPatterns3180[i];
    }
    return nullptr;
}
