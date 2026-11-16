package com.hozinking.pvzinjector

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.hozinking.pvzinjector.databinding.ActivityMainBinding

/**
 * Hozin PvZ Injector v1.3 — launcher root untuk Plants vs Zombies 2 Free
 * (com.ea.game.pvzfree_row). Game TIDAK dibundel — user install sendiri
 * dari Play Store / APKPure.
 *
 * ALUR v1.1 (otomatis penuh — meniru pola RootInjector yang diminta user):
 *   Tap "Inject ke PvZ2" → cek root → cek install/versi → bila game belum
 *   jalan, OTOMATIS launch game → tunggu PID → tunggu libpvz.so termuat
 *   → inject otomatis. TIDAK ADA lagi langkah manual "buka gamenya dulu".
 *   Logo/status mengambang (FloatingOverlay) muncul begitu proses dimulai
 *   dan tetap tampil apa pun hasilnya — anti gagal.
 *
 * v1.3 — mekanisme injector di-port dari Traffic Rider (TR v2.5,
 * terbukti jalan di HP user): jeda settle 3 dtk setelah libpvz.so
 * termuat (jangan dlopen saat main thread masih memegang loader lock —
 * akar hang v1.2), retry dlopen s.d. 3x (cache game → native → cache
 * game) dengan cek maps antar percobaan, anti-double-load (jangan dlopen
 * bila payload sudah ter-map), verifikasi alamat dlopen remote di
 * mapping x-perm libdl.so. Inti mekanisme SAMA dengan TR (ptrace +
 * remote dlopen, kerangka RootInjector) — yang di-port adalah hardening
 * lapangan TR. Constructor payload non-blocking + timeout 10 dtk +
 * retry thread tidur tetap ada dari rencana v1.3 awal. Zygisk DITAHAN
 * untuk v1.3 (perintah user: pakai punya TR dulu).
 *
 * AGNOSTIK VERSI: aplikasi TIDAK menolak berdasarkan versionCode. Gate
 * ada di payload — semua 17 simbol hook harus ter-resolve. Setelah inject,
 * aplikasi membaca file status payload (±10 dtk) dan menampilkan READY
 * atau UNSUPPORTED + simbol mana yang gagal.
 *
 * Diagnosis di dalam aplikasi (aturan 14 Nov — JANGAN suruh user jalankan
 * Termux/logcat): log injector langkah-demi-langkah tampil di layar +
 * tombol "Salin diagnosis".
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    @Volatile
    private var autoRunning = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.textInfo.text =
            "Target: Plants vs Zombies 2 Free (versi apa pun yang simbolnya lengkap)\n" +
            "Tap \"Inject ke PvZ2\" — game otomatis diluncurkan bila belum jalan,\n" +
            "lalu inject otomatis. Logo status mengambang muncul selama proses.\n" +
            "Masuk level Adventure, nyalakan toggle di menu dalam game.\n" +
            "Solo/offline saja. Tanpa jaminan anti-ban."

        // Izin overlay diminta sekali di awal supaya logo floating bisa
        // tampil saat inject; bila ditolak, alur tetap jalan tanpa overlay.
        if (!FloatingOverlay.canDrawOverlays(this)) {
            FloatingOverlay.requestPermission(this)
            log("Izin 'Tampilkan di atas aplikasi lain' diminta — izinkan supaya logo status mengambang bisa muncul.")
        }

        binding.btnCheckRoot.setOnClickListener {
            Thread {
                val available = RootShell.isRootAvailable()
                log(if (available) "root: available" else "root: NOT available — butuh HP root")
            }.start()
        }

        binding.btnCheckGame.setOnClickListener {
            Thread {
                log(InjectorBridge.checkGame(this))
            }.start()
        }

        binding.btnInject.setOnClickListener {
            if (autoRunning) {
                log("proses inject masih jalan — tunggu selesai")
                return@setOnClickListener
            }
            Thread { runAutoInject() }.start()
        }

        binding.btnCopyDiag.setOnClickListener {
            val text = binding.textLog.text.toString()
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("HozinPvZ diagnosis", text))
            Toast.makeText(this, "Diagnosis disalin", Toast.LENGTH_SHORT).show()
        }
    }

    /** Seluruh alur inject otomatis, dengan progres ke overlay + log. */
    private fun runAutoInject() {
        autoRunning = true
        try {
            log("== Inject v1.3 — alur otomatis ==")
            FloatingOverlay.show(this, "⏳ Hozin PvZ: memulai…")

            // 1. Root.
            if (!RootShell.isRootAvailable()) {
                log("root: NOT available — butuh HP root")
                FloatingOverlay.setStatus("❌ Hozin PvZ: root tidak tersedia")
                return
            }
            log("root: available")

            // 2. Install / versi (cross-check PID — jangan pernah bilang
            // "TIDAK terinstall" saat game jalan). TIDAK ADA penolakan
            // berdasarkan versionCode di sini — gate ada di payload
            // (simbol hook), bukan di aplikasi.
            val check = InjectorBridge.checkGame(this)
            log(check)
            val version = InjectorBridge.installedVersionCode(this)
            val versionName = InjectorBridge.installedVersionName(this)
            if (version != null) {
                log("versi terinstall: ${versionName ?: "?"} (code $version) — ditampilkan apa adanya")
            }
            if (version == null && InjectorBridge.findPid(InjectorBridge.TARGET_PACKAGE) == null) {
                FloatingOverlay.setStatus("❌ Hozin PvZ: game belum terinstall")
                return
            }

            // 3. Game belum jalan → luncurkan otomatis.
            var pid = InjectorBridge.findPid(InjectorBridge.TARGET_PACKAGE)
            if (pid == null) {
                log("PvZ2 belum jalan — meluncurkan otomatis…")
                FloatingOverlay.setStatus("🚀 Hozin PvZ: meluncurkan game…")
                if (!InjectorBridge.launchGame(this)) {
                    log("launch game GAGAL — buka PvZ2 manual lalu tap Inject lagi")
                    FloatingOverlay.setStatus("❌ Hozin PvZ: gagal meluncurkan game")
                    return
                }
                pid = waitForPid(30)
                if (pid == null) {
                    log("game tidak muncul (PID tak ketemu setelah 30 dtk)")
                    FloatingOverlay.setStatus("❌ Hozin PvZ: game tidak muncul")
                    return
                }
            }
            log("pid PvZ2: $pid")

            // 4. Tunggu libpvz.so termuat (maks 45 dtk). Bila lewat, inject
            // tetap dicoba — payload menunggu sendiri sampai 60 dtk.
            FloatingOverlay.setStatus("⏳ Hozin PvZ: menunggu libpvz.so…")
            val libOk = waitForLib(pid, 45)
            if (libOk) {
                log("libpvz.so termuat")
                // TR-port (v1.3) — jeda settle 3 dtk, menunggu main thread
                // game keluar dari rantai dlopen awal (loader lock). Tanpa
                // ini remote-dlopen bisa mendarat saat main thread masih
                // memegang linker lock → dlopen bersarang deadlock →
                // injector + su menggantung, game membeku (bukti TR v2.0/
                // v2.1). Persis mode gagal PvZ v1.2 (dlopen hang, exit=8).
                log("jeda settle 3 dtk biar game selesai load (TR-port)…")
                FloatingOverlay.setStatus("⏳ Hozin PvZ: jeda settle 3 dtk…")
                Thread.sleep(3000)
                val pidAlive = InjectorBridge.findPid(InjectorBridge.TARGET_PACKAGE)
                if (pidAlive != pid) {
                    log("PID game berubah/mati saat jeda settle — batal")
                    FloatingOverlay.setStatus("❌ Hozin PvZ: game mati saat jeda")
                    return
                }
            } else {
                log("libpvz.so belum terlihat setelah 45 dtk — inject tetap dicoba (payload menunggu sendiri)")
            }

            // 5. Inject + diagnosis.
            FloatingOverlay.setStatus("💉 Hozin PvZ: menginject…")
            val result = InjectorBridge.inject(this, pid)
            if (result.diag.isNotEmpty()) log(result.diag)
            log("injector exit=${result.exitCode}")
            // Cek game masih hidup (v1.2): membuktikan/membantah klaim
            // "crash" dari data, bukan tebakan. Injector juga mencatat
            // hal yang sama di diagnosisnya.
            val pidAfter = InjectorBridge.findPid(InjectorBridge.TARGET_PACKAGE)
            log(if (pidAfter != null) "game masih jalan setelah inject (pid $pidAfter)"
                else "game MATI setelah inject — kemungkinan crash saat remote call")
            if (result.exitCode == 0) {
                // dlopen berhasil — tapi READY/UNSUPPORTED diputuskan
                // payload (simbol hook). Tunggu file statusnya ±10 dtk.
                FloatingOverlay.setStatus("⏳ Hozin PvZ: menunggu status payload…")
                val ps = waitForPayloadStatus(10)
                when (ps.status) {
                    "READY" -> {
                        log("payload READY — semua 17 simbol ketemu (BuildID ${ps.buildId}, lib ${ps.libSize} B)")
                        if (!ps.menu) {
                            log("catatan: menu dalam game tidak tampil (eglSwapBuffers tak ketemu) — fitur tetap ter-hook, toggle tidak bisa diubah")
                        }
                        log("inject OK — kembali ke game, menu mod muncul di layar")
                        FloatingOverlay.setStatus("✅ Hozin PvZ: BERHASIL — menu di dalam game")
                    }
                    "UNSUPPORTED" -> {
                        val v = versionName ?: "?"
                        val c = version ?: -1
                        log("versi $v (code $c) BELUM didukung — simbol tidak ditemukan: ${ps.failed}")
                        log("BuildID libpvz.so: ${ps.buildId}")
                        FloatingOverlay.setStatus("❌ Hozin PvZ: versi belum didukung — simbol ${ps.failed} tidak ketemu")
                    }
                    else -> {
                        log("inject exit 0 (dlopen OK) tapi status payload tak terbaca setelah 10 dtk — " +
                            "payload mungkin masih init, atau file status tak bisa ditulis. Cek lagi lewat tombol Cek PvZ2 / tap Inject ulang.")
                        FloatingOverlay.setStatus("⚠️ Hozin PvZ: status payload tak terbaca")
                    }
                }
            } else {
                val reason = InjectorBridge.failureReason(result.exitCode)
                log("inject GAGAL — $reason")
                FloatingOverlay.setStatus("❌ Hozin PvZ: GAGAL — $reason")
            }
        } finally {
            autoRunning = false
        }
    }

    /** Poll PID sampai timeout detik; null bila tak muncul. */
    private fun waitForPid(timeoutSec: Int): Int? {
        repeat(timeoutSec * 2) {
            val pid = InjectorBridge.findPid(InjectorBridge.TARGET_PACKAGE)
            if (pid != null) return pid
            Thread.sleep(500)
        }
        return null
    }

    /** Poll file status payload sampai timeout detik; status "" bila tak muncul. */
    private fun waitForPayloadStatus(timeoutSec: Int): InjectorBridge.PayloadStatus {
        repeat(timeoutSec * 2) {
            val raw = InjectorBridge.readPayloadStatus()
            val ps = InjectorBridge.parsePayloadStatus(raw)
            if (ps.status.isNotEmpty()) return ps
            Thread.sleep(500)
        }
        return InjectorBridge.PayloadStatus("", "-", "-", "-", false, "")
    }

    /** Poll libpvz.so di /proc/<pid>/maps sampai timeout detik. */
    private fun waitForLib(pid: Int, timeoutSec: Int): Boolean {
        var waited = 0
        while (waited < timeoutSec) {
            if (InjectorBridge.isLibLoaded(pid, InjectorBridge.TARGET_LIB)) return true
            Thread.sleep(1000)
            waited++
            if (waited % 10 == 0) {
                FloatingOverlay.setStatus("⏳ Hozin PvZ: menunggu libpvz.so… ${waited}d")
            }
        }
        return InjectorBridge.isLibLoaded(pid, InjectorBridge.TARGET_LIB)
    }

    private fun log(line: String) {
        runOnUiThread {
            binding.textLog.append(line + "\n")
        }
    }
}
