# Hozin PvZ Injector v1.1

Root injector untuk **Plants vs Zombies 2 Free** (`com.ea.game.pvzfree_row`)
di HP Android root (arm64-v8a saja). **Solo/offline saja** — mod hanya
berpengaruh di level Adventure.

**v1.1 AGNOSTIK VERSI:** injector TIDAK lagi memakai whitelist versionCode.
Gate utama = semua 17 simbol hook kunci berhasil di-resolve (`dlsym()`
nama mangled dulu, lalu pattern-scan generik, lalu pattern-scan 3180).
Bila semua simbol ketemu → JALAN, apa pun versionCode-nya (3180, 3190,
dst). Bila ada simbol tidak ketemu → tolak dengan pesan jelas di UI
("versi X (code Y) belum didukung — simbol Z tidak ditemukan").
"Kebal update" = tahan update minor selama signature C++ fungsi inti tak
berubah — BUKAN jaminan mutlak selamanya.

Game TIDAK dibundel — install sendiri dari Play Store / APKPure.

## Fitur v1.1

| Fitur | Mekanisme |
|---|---|
| Sun tak habis | Hook `Board::TakeSunMoney` (return true tanpa kurangi) + `Board::CanTakeSunMoney` (selalu true) |
| 1-hit kill zombie | Hook `Zombie::TakeDamage` — damage dipaksa 100000 |
| Tanam gratis | Hook `Board::GetCurrentPlantCost` — biaya jadi 0 |
| Super mower selalu aktif | Hook `Board::InitLawnMowers` → panggil `Board::SetSuperMowerMode(true)` |
| Tambah Sun +5000 | Tombol di menu, panggil `Board::AddSunMoney` (cap internal game 9990) |

**Yang TIDAK ADA (sengaja):** coins/gems/IAP apa pun, unlock tanaman via
store, No Ads, bypass lisensi / Play Integrity / `isDeviceRooted`, mode
Arena/ranking. **Tanaman kebal, tanpa-cooldown seed, Plant Food DICORET**
— titik hook-nya belum terbukti dari simbol; butuh probe runtime sebelum
dibuat (bukan ditebak).

## Cara pakai (POCO / HP root)

1. Install PvZ2 asli (versi apa pun dari Play Store).
2. Buka Hozin PvZ Injector → tap **Inject ke PvZ2**. Game **otomatis
   diluncurkan** bila belum jalan — tidak perlu buka game manual dulu.
3. Logo/status mengambang muncul selama proses (juga saat inject gagal)
   — tap untuk kembali ke aplikasi / retry.
4. Bila inject OK, kembali ke game — menu "Hozin PvZ Injector v1.1"
   muncul di layar. Bila versi belum didukung, layar diagnosis
   menampilkan simbol mana yang gagal + tombol **Salin diagnosis**.
5. Masuk level **Adventure**, nyalakan toggle di menu.
6. Sentuhan pada menu juga diteruskan ke game — **pause dulu** sebelum
   ubah toggle.

## Keamanan desain

- **Fail-closed (v1.1):** sebelum hook apa pun, payload memverifikasi
  package benar + `libpvz.so` termuat. Ukuran + BuildID `libpvz.so`
  HANYA dicatat (log + file status), BUKAN gate. Lalu gate utama: semua
  17 simbol hook kunci harus ter-resolve. Satu saja gagal → payload
  keluar TANPA hook, file status menulis `UNSUPPORTED` + daftar simbol
  yang gagal — UI menampilkan alasannya, bukan "TIDAK terinstall".
- **Gate mode (satu fungsi terpusat):** hook hanya berpengaruh bila
  `LawnApp::IsAdventureMode()` true dan semua mode lain (Challenge,
  Puzzle, Survival, Last Stand, I-Zombie, Piñata) false. Mode lain /
  tak dikenali = hook pass-through ke fungsi asli.
- **Kebal update:** resolusi alamat garis pertama `dlsym()` nama mangled
  C++ lengkap (stabil selama signature tak berubah); cadangan pattern-scan
  2-jendela (prologue + mid-body, cross-check): tabel GENERIK dulu
  (`payload/patterns_generic.h`), lalu tabel per-versi
  (`payload/patterns_3180.h`; `patterns_3190.h` ditambahkan begitu dump
  3.19.0 tersedia). Versi game baru yang simbolnya berubah = injector
  menolak jalan dengan alasan jelas, bukan nekat.
- **Tanpa toggle palsu:** v1.1 all-or-nothing — bila satu simbol kunci
  gagal, TIDAK ADA hook yang dipasang sama sekali.
- **Tidak menyentuh:** Java/Dex, Nimble, Billing, lisensi Play, APK game
  (APK tetap asli + ter-sign EA).

## Status verifikasi versi (jujur, 16 Nov 2026)

- **3.18.0 (3180):** terverifikasi penuh dari dump (simbol + pola 17/17,
  BuildID `8e40bdc9…`, lib 50.117.680 B).
- **3.19.0 (3190):** game di HP user sudah auto-update ke 3.19.0, TAPI
  dump 3190 BELUM tersedia di mirror publik mana pun (APKPure API +
  Uptodown + APKFab semua masih listing 3.18.0 sebagai terbaru).
  Verifikasi 3190 dilakukan lewat log payload di HP saat tes POCO:
  file status menulis per-simbol `dlsym` / `pattern-generic` /
  `pattern-3180` / `GAGAL`, jadi ketahuan persis simbol mana (bila ada)
  yang berubah di 3190. Tabel `patterns_generic.h` saat ini diturunkan
  dari 3180 — klaim "identik lintas versi" baru terbukti begitu dump
  3190 dibandingkan.

## Risiko (jujur)

- **Tidak ada jaminan anti-ban.** Play Integrity token bisa ditolak server
  karena root / injector terdeteksi. Injector tidak menyentuhnya, tapi
  risiko root itu sendiri tetap ada. Main di akun utama = risiko sendiri.
- **Tanpa runtime probe**, v1.0/v1.1 dibangun dari bukti REA statis —
  tes POCO adalah pembuktian pertama. Bila satu fitur tidak jalan di HP,
  laporkan lewat tombol **Salin diagnosis** di aplikasi (logcat tag
  `HozinPvZ`) — jangan asumsi.
- Bila EA men-strip `.dynsym` di update berikut, dlsym gagal dan injector
  beralih ke pattern-scan; bila pola tak cocok, injector menolak jalan
  dengan alasan jelas.

## Arsitektur

- **app** (Kotlin) — UI cek root, cek install/versi (PackageManager API +
  scan `/proc`, TANPA `pm`/`cmd package`), auto-launch game, tunggu PID +
  `libpvz.so`, trigger inject, baca file status payload, logo/status
  mengambang (overlay `SYSTEM_ALERT_WINDOW`), layar diagnosis + tombol
  salin. Bicara ke satu shell `su` persisten. Payload disalin dulu ke
  `/data/local/tmp/hozinpvz_payload.so` agar proses game bisa dlopen.
- **injector** (C++, `cpp/injector/`) — binary PIE mandiri, dijalankan root
  via `su -c`: ptrace-attach ke PID target, resolve `dlopen`/`mmap` di
  dalamnya, alokasi scratch, tulis path payload, panggil `dlopen` remote.
  Log langkah-demi-langkah ke stdout + file
  `/data/local/tmp/hozinpvz_inject.log`, exit code bermakna
  (0 OK; 2 usage; 3 local module; 4 attach; 5 remote resolve; 6 remote
  mmap; 7 write mem; 8 dlopen call; 9 dlopen NULL).
  (Pola RootInjector generik yang sudah terbukti.)
- **payload** (C++, `cpp/payload/`) — library yang masuk ke proses game:
  verifikasi target (log-only BuildID/ukuran) → resolver all-or-nothing
  (dlsym → pattern-generik → pattern-3180) → hook Dobby → menu ImGui
  native (hook `eglSwapBuffers`, input dari hook
  `InputConsumer::consume`) → gate mode → tulis file status
  (`/data/local/tmp/hozinpvz_payload.log`, fallback cache dir game).
- **Dobby** — diambil saat build via FetchContent + 5 patch NDK modern
  (pola yang sama dengan BUSSID/TR/HCR). **Dear ImGui 1.88 WIP** (MIT) —
  vendored di `cpp/thirdparty/imgui/`.

## Build

APK HANYA dibangun di GitHub Actions (push ke `main` → build + rilis
otomatis `v1.1`). Keystore debug persisten proyek dipulihkan dari secret
`DEBUG_KEYSTORE_BASE64` (file `debug.keystore` di root repo, di-.gitignore,
JANGAN PERNAH push).

## REA & audit

- `~/workspace/rea-pvz2/REPORT.md` — laporan REA lengkap (engine, lib,
  target hook, anti-cheat, klasifikasi fitur).
- `~/workspace/rea-pvz2/AUDIT-INJECTOR.md` — desain injector (arsitektur,
  fail-closed, kebal update, kerangka, gate, risiko).
