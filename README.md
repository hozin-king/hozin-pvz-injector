# Hozin PvZ Injector v1.0

Root injector untuk **Plants vs Zombies 2 Free** (`com.ea.game.pvzfree_row`,
3.18.0 / versionCode 3180) di HP Android root (arm64-v8a saja).
**Solo/offline saja** — mod hanya berpengaruh di level Adventure.

Game TIDAK dibundel — install sendiri dari Play Store / APKPure.

## Fitur v1.0

| Fitur | Mekanisme |
|---|---|
| Sun tak habis | Hook `Board::TakeSunMoney` (return true tanpa kurangi) + `Board::CanTakeSunMoney` (selalu true) |
| 1-hit kill zombie | Hook `Zombie::TakeDamage` — damage dipaksa 100000 |
| Tanam gratis | Hook `Board::GetCurrentPlantCost` — biaya jadi 0 |
| Super mower selalu aktif | Hook `Board::InitLawnMowers` → panggil `Board::SetSuperMowerMode(true)` |
| Tambah Sun +5000 | Tombol di menu, panggil `Board::AddSunMoney` (cap internal game 9990) |

**Yang TIDAK ADA (sengaja):** coins/gems/IAP apa pun, unlock tanaman via
store, No Ads, bypass lisensi / Play Integrity / `isDeviceRooted`, mode
Arena/ranking. **Tanaman kebal, tanpa-cooldown seed, Plant Food DICORET
dari v1.0** — titik hook-nya belum terbukti dari simbol; butuh probe
runtime sebelum dibuat (bukan ditebak).

## Cara pakai (POCO / HP root)

1. Install PvZ2 3.18.0 asli, buka game sampai **main menu** (jangan inject
   saat download resource / cek lisensi pertama jalan).
2. Buka Hozin PvZ Injector → **Cek PvZ2** (harus 3.18.0 / 3180) → **Inject**.
3. Kembali ke game — menu "Hozin PvZ Injector v1.0" muncul di layar.
4. Masuk level **Adventure**, nyalakan toggle di menu.
5. Sentuhan pada menu juga diteruskan ke game — **pause dulu** sebelum
   ubah toggle.

## Keamanan desain

- **Fail-closed:** sebelum hook apa pun, payload memverifikasi package +
  ukuran + BuildID `libpvz.so` (`8e40bdc9…`). Satu saja gagal → payload
  keluar diam-diam, tanpa menu, tanpa hook setengah jalan.
- **Gate mode (satu fungsi terpusat):** hook hanya berpengaruh bila
  `LawnApp::IsAdventureMode()` true dan semua mode lain (Challenge,
  Puzzle, Survival, Last Stand, I-Zombie, Piñata) false. Mode lain /
  tak dikenali = hook pass-through ke fungsi asli.
- **Kebal update:** resolusi alamat garis pertama `dlsym()` nama mangled
  C++ lengkap (stabil selama signature tak berubah); cadangan pattern-scan
  2-jendela (prologue + mid-body, cross-check) di `payload/patterns_3180.h`.
  Versi game baru = file pola baru + REA ulang — injector menolak jalan
  di versi tak dikenal, bukan nekat.
- **Tanpa toggle palsu:** fitur yang hook-nya gagal di-resolve tidak
  muncul sebagai toggle di menu (ditampilkan sebagai "tidak tersedia").
- **Tidak menyentuh:** Java/Dex, Nimble, Billing, lisensi Play, APK game
  (APK tetap asli + ter-sign EA).

## Risiko (jujur)

- **Tidak ada jaminan anti-ban.** Play Integrity token bisa ditolak server
  karena root / injector terdeteksi. Injector tidak menyentuhnya, tapi
  risiko root itu sendiri tetap ada. Main di akun utama = risiko sendiri.
- **Tanpa runtime probe**, v1.0 dibangun dari bukti REA statis — tes POCO
  adalah pembuktian pertama. Bila satu fitur tidak jalan di HP, laporkan
  (logcat tag `HozinPvZ`) — jangan asumsi.
- Bila EA men-strip `.dynsym` di update berikut, dlsym gagal dan injector
  beralih ke pattern-scan; bila pola tak cocok, injector menolak jalan.

## Arsitektur

- **app** (Kotlin) — UI cek root, cek versi PvZ2, cari PID, trigger inject.
  Bicara ke satu shell `su` persisten. Payload disalin dulu ke
  `/data/local/tmp/hozinpvz_payload.so` agar proses game bisa dlopen.
- **injector** (C++, `cpp/injector/`) — binary PIE mandiri, dijalankan root
  via `su -c`: ptrace-attach ke PID target, resolve `dlopen`/`mmap` di
  dalamnya, alokasi scratch, tulis path payload, panggil `dlopen` remote.
  (Pola RootInjector generik yang sudah terbukti.)
- **payload** (C++, `cpp/payload/`) — library yang masuk ke proses game:
  verifikasi target → resolver (dlsym + pattern-scan) → hook Dobby →
  menu ImGui native (hook `eglSwapBuffers`, input dari hook
  `InputConsumer::consume`) → gate mode.
- **Dobby** — diambil saat build via FetchContent + 5 patch NDK modern
  (pola yang sama dengan BUSSID/TR/HCR). **Dear ImGui 1.88 WIP** (MIT) —
  vendored di `cpp/thirdparty/imgui/`.

## Build

APK HANYA dibangun di GitHub Actions (push ke `main` → build + rilis
otomatis `v1.0.0`). Keystore debug persisten proyek dipulihkan dari secret
`DEBUG_KEYSTORE_BASE64` (file `debug.keystore` di root repo, di-.gitignore,
JANGAN PERNAH push).

## REA & audit

- `~/workspace/rea-pvz2/REPORT.md` — laporan REA lengkap (engine, lib,
  target hook, anti-cheat, klasifikasi fitur).
- `~/workspace/rea-pvz2/AUDIT-INJECTOR.md` — desain injector (arsitektur,
  fail-closed, kebal update, kerangka, gate, risiko).
