package com.hozinking.pvzinjector

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import java.io.File

/**
 * Hozin PvZ Injector v1.1 — jembatan Kotlin ↔ native injector.
 *
 * v1.2: staging payload PINDAH ke cache game sendiri (app_data_file) —
 * tes POCO v1.1: dlopen NULL dari /data/local/tmp (shell_data_file,
 * untrusted_app tak bisa baca). Injector v1.2 menangkap dlerror() +
 * fallback android_dlopen_ext via fd.
 *
 * Pelajaran v1.0 (tes POCO 21:53):
 * - "PvZ2 TIDAK terinstall" padahal PID game ketemu. Akar: manifest v1.0
 *   tanpa <queries> → di Android 11+ getPackageInfo() untuk aplikasi lain
 *   selalu lempar NameNotFoundException. v1.1 menambah <queries> DAN
 *   cross-check: bila proses game JALAN, game PASTI terinstall — jangan
 *   pernah cetak "TIDAK terinstall" saat PID ada (satu sumber kebenaran).
 * - JANGAN PERNAH pakai `pm` / `cmd package` / `dumpsys package` untuk
 *   deteksi (rusak di POCO user, pelajaran 28 Okt 2026). Deteksi hanya
 *   via PackageManager API + scan /proc (pidof + fallback cmdline).
 *
 * v1.1 AGNOSTIK VERSI: TIDAK ADA lagi whitelist versionCode. Gate utama
 * ada di payload: semua 17 simbol hook kunci harus ter-resolve (dlsym →
 * pattern-generik → pattern-3180). Aplikasi hanya menampilkan versi
 * terinstall apa adanya + membaca file status payload
 * (hozinpvz_payload.log) untuk tahu READY vs UNSUPPORTED + simbol mana
 * yang gagal.
 */
object InjectorBridge {

    const val TARGET_PACKAGE = "com.ea.game.pvzfree_row"
    const val TARGET_LIB = "libpvz.so"

    private const val INJECTOR_LIB = "libinjector.so"
    private const val PAYLOAD_LIB = "libpayload.so"
    private const val PAYLOAD_TMP = "/data/local/tmp/hozinpvz_payload.so"

    /**
     * Lokasi UTAMA payload (v1.2): direktori cache game sendiri.
     * Bukti tes POCO v1.1: dlopen NULL dari /data/local/tmp — file di sana
     * berkonteks shell_data_file dan proses game (untrusted_app) TIDAK
     * bisa membacanya (SELinux). File di cache game berkonteks
     * app_data_file milik game sendiri → bisa dibaca/di-dlopen.
     */
    private const val PAYLOAD_GAME =
        "/data/data/com.ea.game.pvzfree_row/cache/hozinpvz_payload.so"
    private const val GAME_CACHE_DIR = "/data/data/com.ea.game.pvzfree_row/cache"
    private const val GAME_DATA_DIR = "/data/data/com.ea.game.pvzfree_row"
    const val INJECT_LOG = "/data/local/tmp/hozinpvz_inject.log"

    /** Dua lokasi file status payload (payload menulis ke yang pertama bisa). */
    private const val PAYLOAD_STATUS_TMP = "/data/local/tmp/hozinpvz_payload.log"
    private const val PAYLOAD_STATUS_CACHE =
        "/data/data/com.ea.game.pvzfree_row/cache/hozinpvz_payload.log"

    /** Marker constructor payload (v1.3) — apakah constructor sempat kembali. */
    private const val CTOR_LOG_CACHE =
        "/data/data/com.ea.game.pvzfree_row/cache/hozinpvz_ctor.log"

    /** Hasil inject lengkap dengan diagnosis (stdout injector + file log). */
    data class InjectResult(val exitCode: Int, val output: String, val diag: String)

    /** Status payload, diparse dari hozinpvz_payload.log. */
    data class PayloadStatus(
        val status: String,      // READY | UNSUPPORTED | "" (tak terbaca)
        val failed: String,      // daftar simbol gagal, "-" bila tak ada
        val buildId: String,
        val libSize: String,
        val menu: Boolean,
        val raw: String
    )

    fun injectorPath(context: Context): String =
        File(context.applicationInfo.nativeLibraryDir, INJECTOR_LIB).absolutePath

    fun payloadPath(context: Context): String =
        File(context.applicationInfo.nativeLibraryDir, PAYLOAD_LIB).absolutePath

    /**
     * Cek PvZ2 terinstall + tampilkan versi apa adanya (TANPA penilaian
     * cocok/tidak — itu urusan payload, bukan aplikasi). Cross-check
     * dengan PID: proses yang jalan = game terinstall, apa pun kata
     * PackageManager.
     */
    fun checkGame(context: Context): String {
        val pid = findPid(TARGET_PACKAGE)
        val pidNote = if (pid != null) " (jalan, pid $pid)" else " (belum jalan)"
        val info = try {
            context.packageManager.getPackageInfo(TARGET_PACKAGE, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
        if (info != null) {
            val code = info.longVersionCode
            val name = info.versionName ?: "?"
            return "PvZ2 terinstall: $name ($code)$pidNote — didukung bila semua simbol hook ketemu (payload yang memutuskan)"
        }
        // PackageManager tak bisa melihat paketnya (mis. <queries> hilang):
        // bila prosesnya jalan, game PASTI terinstall — laporkan begitu.
        if (pid != null) {
            return "PvZ2 JALAN (pid $pid) tapi info versi tak terbaca via PackageManager — " +
                "inject tetap dicoba, payload yang memverifikasi (fail-closed)"
        }
        return "PvZ2 TIDAK terinstall — install com.ea.game.pvzfree_row dari Play Store dulu"
    }

    /** Versi terinstall apa adanya (null bila tak terbaca). */
    fun installedVersionCode(context: Context): Long? {
        return try {
            context.packageManager.getPackageInfo(TARGET_PACKAGE, 0).longVersionCode
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    /** Nama versi terinstall apa adanya (null bila tak terbaca). */
    fun installedVersionName(context: Context): String? {
        return try {
            context.packageManager.getPackageInfo(TARGET_PACKAGE, 0).versionName
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    /** Baca file status payload (dua lokasi, via root). "" bila tak ada. */
    fun readPayloadStatus(): String {
        val r = RootShell.exec(
            "cat '$PAYLOAD_STATUS_TMP' 2>/dev/null || cat '$PAYLOAD_STATUS_CACHE' 2>/dev/null"
        )
        return r.output.trim()
    }

    /** Parse isi file status payload. status "" = file belum ada/tak terbaca. */
    fun parsePayloadStatus(raw: String): PayloadStatus {
        if (raw.isEmpty()) return PayloadStatus("", "-", "-", "-", false, "")
        var status = ""
        var failed = "-"
        var buildId = "-"
        var libSize = "-"
        var menu = false
        for (line in raw.lines()) {
            val (k, v) = line.split("=", limit = 2).let {
                if (it.size == 2) it[0] to it[1] else it[0] to ""
            }
            when (k) {
                "STATUS" -> status = v
                "FAILED" -> failed = v
                "BUILDID" -> buildId = v
                "LIBSIZE" -> libSize = v
                "MENU" -> menu = (v == "1")
            }
        }
        return PayloadStatus(status, failed, buildId, libSize, menu, raw)
    }

    /**
     * Defensive chmod in case the native lib directory wasn't extracted with
     * the executable bit set for this file. Cheap, safe to call every time.
     */
    fun ensureExecutable(context: Context): Boolean {
        val result = RootShell.exec("chmod 755 '${injectorPath(context)}'")
        return result.exitCode == 0
    }

    /** pidof dulu; bila kosong, scan /proc/<pid>/cmdline via su. */
    fun findPid(processName: String): Int? {
        val r = RootShell.exec("pidof $processName")
        val pid = r.output.trim().split(Regex("\\s+")).firstOrNull()?.toIntOrNull()
        if (r.exitCode == 0 && pid != null) return pid
        val safe = processName.replace(".", "[.]")
        val scan = "for p in /proc/[0-9]*/cmdline; do " +
            "if grep -a -q '^$safe' \"\$p\" 2>/dev/null; then " +
            "echo \"\$p\" | cut -d/ -f3; fi; done"
        val r2 = RootShell.exec(scan)
        return r2.output.trim().split(Regex("\\s+")).firstOrNull()?.toIntOrNull()
    }

    /** Apakah lib sudah termuat di proses game (poll /proc/<pid>/maps). */
    fun isLibLoaded(pid: Int, libName: String): Boolean {
        val r = RootShell.exec("grep -q '$libName' /proc/$pid/maps")
        return r.exitCode == 0
    }

    /**
     * TR-port (v1.3) — anti-double-load: true bila payload sudah ter-map
     * di proses game (file staging hozinpvz_payload.so ATAU salinan native
     * libpayload.so — pola "payload.so" cocok untuk keduanya). dlopen
     * kedua = constructor kedua = double DobbyHook pada alamat yang sama
     * = game crash (bukti TR v2.2). Dicek SEBELUM tiap percobaan dlopen.
     */
    fun isPayloadLoaded(pid: Int): Boolean = isLibLoaded(pid, "payload\\.so")

    /**
     * Luncurkan game. Utama: launch intent PackageManager (butuh <queries>
     * — sudah ada di manifest v1.1). Cadangan: monkey via su (tak butuh
     * nama activity).
     */
    fun launchGame(context: Context): Boolean {
        try {
            val intent = context.packageManager.getLaunchIntentForPackage(TARGET_PACKAGE)
            if (intent != null) {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                return true
            }
        } catch (e: Exception) {
            // jatuh ke monkey di bawah
        }
        val r = RootShell.exec(
            "monkey -p $TARGET_PACKAGE -c android.intent.category.LAUNCHER 1"
        )
        return r.exitCode == 0
    }

    /**
     * Salin payload ke lokasi yang BISA di-dlopen proses game.
     * v1.2 — utama: cache game sendiri. File disalin root lalu disamakan
     * owner (UID game) + konteks SELinux dengan direktori cache game
     * (chcon --reference, termasuk kategori MLS) + chmod 755. Bila gagal
     * (mis. direktori game tak bisa ditulis), cadangan: /data/local/tmp
     * seperti v1.1 — injector v1.2 menangkap dlerror + mencoba
     * android_dlopen_ext bila jalur ini yang dipakai.
     */
    private fun stagePayload(context: Context): String? {
        val src = payloadPath(context)
        val gameStage = RootShell.exec(
            "D='$GAME_CACHE_DIR'; " +
            "mkdir -p \"\$D\" && cp '$src' '$PAYLOAD_GAME' && " +
            "U=\$(stat -c %u '$GAME_DATA_DIR' 2>/dev/null); " +
            "if [ -n \"\$U\" ]; then chown \"\$U\" '$PAYLOAD_GAME' 2>/dev/null; fi; " +
            "chmod 755 '$PAYLOAD_GAME' && " +
            "chcon --reference=\"\$D\" '$PAYLOAD_GAME' 2>/dev/null; " +
            "ls -l '$PAYLOAD_GAME'"
        )
        if (gameStage.exitCode == 0) return PAYLOAD_GAME
        val r = RootShell.exec("cp '$src' '$PAYLOAD_TMP' && chmod 755 '$PAYLOAD_TMP'")
        return if (r.exitCode == 0) PAYLOAD_TMP else null
    }

    /**
     * Inject + kumpulkan diagnosis (stdout; bila kosong, baca file log).
     *
     * TR-port (v1.3) — retry s.d. 3x: [cache game → native lib → cache
     * game] (TR: [/data/local/tmp → native → /data/local/tmp]; PvZ memakai
     * cache game sebagai jalur utama karena /data/local/tmp terbukti tak
     * bisa dibaca proses PvZ — v1.1). Antar percobaan: jeda 1 dtk + cek
     * maps — dlopen percobaan sebelumnya bisa selesai TERLAMBAT setelah
     * timeout, dan dlopen kedua ke payload yang sudah ter-map = crash.
     * Bila payload sudah ter-load sebelum percobaan pertama (mis. tap
     * Inject dua kali), dlopen dilewati total.
     */
    fun inject(context: Context, pid: Int): InjectResult {
        ensureExecutable(context)
        if (isPayloadLoaded(pid)) {
            return InjectResult(
                0, "",
                "payload sudah ter-load di pid $pid — lewati dlopen, langsung tunggu status"
            )
        }
        val staged = stagePayload(context)
        // Fallback: coba path asli bila staging gagal (mis. /data/local/tmp
        // tak bisa ditulis) — injector yang akan membuktikan bisa/tidak.
        val primary = staged ?: payloadPath(context)
        val attempts = arrayOf(primary, payloadPath(context), primary)
        var last: InjectResult? = null
        for ((i, path) in attempts.withIndex()) {
            if (i > 0) {
                Thread.sleep(1000)
                // Percobaan sebelumnya mungkin sudah me-load payload tapi
                // hasilnya tak terbaca — cek maps dulu (TR-port).
                if (isPayloadLoaded(pid)) {
                    return InjectResult(
                        0, "",
                        "payload ter-load (percobaan sebelumnya) — stop retry\n" +
                            (last?.diag ?: "")
                    )
                }
            }
            val r = RootShell.exec("${injectorPath(context)} $pid $path")
            var diag = r.output.trim()
            if (diag.isEmpty()) {
                val log = RootShell.exec("cat '$INJECT_LOG' 2>/dev/null")
                diag = log.output.trim()
            }
            // v1.3: marker constructor payload (apakah constructor sempat
            // kembali — membedakan "constructor tak kembali" dari "remote
            // call yang timeout" saat dlopen hang).
            val ctor = RootShell.exec("cat '$CTOR_LOG_CACHE' 2>/dev/null").output.trim()
            if (ctor.isNotEmpty()) diag = "$diag\nctor log:\n$ctor"
            // Catat jalur load yang dipakai tiap percobaan — penting saat
            // dlopen gagal (bedakan cache game vs native di diagnosis).
            if (diag.isNotEmpty()) diag = "percobaan ${i + 1}/3 (TR-port) — payload path dipakai: $path\n$diag"
            last = InjectResult(r.exitCode, r.output, diag)
            if (r.exitCode == 0) return last
            // Timeout (8) & NULL (9) sama-sama dicoba ulang — penyebabnya
            // bisa transien (loader lock). Tidak ada kode "crash" tersendiri
            // di injector PvZ; bila game mati, percobaan berikut gagal
            // attach dan loop berakhir dengan diagnosisnya.
        }
        return last ?: InjectResult(1, "", "inject gagal tanpa percobaan")
    }

    /** Arti exit code injector (v1.1) dalam bahasa manusia. */
    fun failureReason(exitCode: Int): String = when (exitCode) {
        0 -> "OK"
        2 -> "argumen injector salah (bug aplikasi)"
        3 -> "libdl/libc tidak ketemu di proses injector sendiri"
        4 -> "ptrace attach ditolak — root tidak aktif / SELinux menolak"
        5 -> "libc/libdl tidak ketemu di proses game (layout maps aneh)"
        6 -> "alokasi memori di proses game gagal"
        7 -> "tulis path payload ke memori game gagal"
        8 -> "panggilan dlopen di game tidak selesai (timeout 10 dtk + retry thread lain, lalu retry 3x; bila tetap gagal, salin diagnosis)"
        9 -> "dlopen payload ditolak — baca baris dlerror di diagnosis (alasan linker yang sebenarnya)"
        else -> "gagal tak dikenal (exit=$exitCode)"
    }
}
