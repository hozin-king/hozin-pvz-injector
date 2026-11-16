package com.hozinking.pvzinjector

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.hozinking.pvzinjector.databinding.ActivityMainBinding

/**
 * Hozin PvZ Injector v1.0 — launcher untuk inject payload ke Plants vs
 * Zombies 2 Free (com.ea.game.pvzfree_row, 3.18.0 / 3180) yang SUDAH
 * berjalan di HP root. Game TIDAK dibundel — user install sendiri dari
 * Play Store / APKPure.
 *
 * Alur pakai:
 *   1. Install PvZ2 3.18.0, buka game, tunggu sampai MAIN MENU
 *      (jangan inject saat download resource / cek lisensi).
 *   2. Buka aplikasi ini → Cek PvZ2 → Inject.
 *   3. Kembali ke game — menu "Hozin PvZ Injector v1.0" muncul di layar.
 *   4. Masuk level Adventure, nyalakan toggle yang mau dipakai.
 *   5. Sentuhan pada menu juga diteruskan ke game — pause dulu sebelum
 *      ubah toggle.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.textInfo.text =
            "Target: Plants vs Zombies 2 Free 3.18.0 (code 3180)\n" +
            "1. Buka PvZ2 sampai MAIN MENU (bukan saat download/cek lisensi).\n" +
            "2. Tap \"Cek PvZ2\" lalu \"Inject\".\n" +
            "3. Kembali ke game — menu mod muncul di layar.\n" +
            "4. Mainkan level Adventure, nyalakan toggle di menu.\n" +
            "Solo/offline saja. Tanpa jaminan anti-ban."

        binding.btnCheckRoot.setOnClickListener {
            Thread {
                val available = RootShell.isRootAvailable()
                log(if (available) "root: available" else "root: NOT available — butuh HP root")
            }.start()
        }

        binding.btnCheckGame.setOnClickListener {
            Thread {
                val info = InjectorBridge.checkGame(this)
                log(info)
            }.start()
        }

        binding.btnInject.setOnClickListener {
            Thread {
                val pid = InjectorBridge.findPid(InjectorBridge.TARGET_PACKAGE)
                if (pid == null) {
                    log("PvZ2 tidak jalan — buka gamenya dulu sampai main menu")
                    return@Thread
                }
                log("pid PvZ2: $pid")
                val result = InjectorBridge.inject(this, pid)
                log("injector exit=${result.exitCode} output=${result.output}")
                if (result.exitCode == 0) {
                    log("inject OK — kembali ke game, menu mod muncul di layar")
                } else {
                    log("inject GAGAL — cek root + PvZ2 3.18.0 sudah jalan")
                }
            }.start()
        }
    }

    private fun log(line: String) {
        runOnUiThread {
            binding.textLog.append(line + "\n")
        }
    }
}
