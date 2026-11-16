package com.hozinking.pvzinjector

import android.content.Context
import android.content.pm.PackageManager
import java.io.File

/**
 * libinjector.so dan libpayload.so masuk ke applicationInfo.nativeLibraryDir
 * karena AGP membundelnya di sana seperti native library biasa.
 *
 * Payload TIDAK di-dlopen dari nativeLibraryDir: proses game (UID game)
 * belum tentu bisa membaca direktori privat aplikasi ini. Sebelum inject,
 * payload disalin (via su) ke /data/local/tmp/hozinpvz_payload.so — jalur
 * yang sama dipakai mod BUSSID/TR yang terbukti jalan di POCO — lalu
 * injector dipanggil dengan path itu.
 */
object InjectorBridge {

    const val TARGET_PACKAGE = "com.ea.game.pvzfree_row"
    const val TARGET_VERSION_CODE = 3180L
    const val TARGET_VERSION_NAME = "3.18.0"

    private const val INJECTOR_LIB = "libinjector.so"
    private const val PAYLOAD_LIB = "libpayload.so"
    private const val PAYLOAD_TMP = "/data/local/tmp/hozinpvz_payload.so"

    fun injectorPath(context: Context): String =
        File(context.applicationInfo.nativeLibraryDir, INJECTOR_LIB).absolutePath

    fun payloadPath(context: Context): String =
        File(context.applicationInfo.nativeLibraryDir, PAYLOAD_LIB).absolutePath

    /** Cek PvZ2 terinstall + versionCode cocok (fail-closed di sisi aplikasi). */
    fun checkGame(context: Context): String {
        return try {
            val pm = context.packageManager
            val info = pm.getPackageInfo(TARGET_PACKAGE, 0)
            val code = info.longVersionCode
            val name = info.versionName ?: "?"
            if (code == TARGET_VERSION_CODE) {
                "PvZ2 terinstall: $name ($code) — COCOK"
            } else {
                "PvZ2 terinstall: $name ($code) — TIDAK COCOK, butuh $TARGET_VERSION_NAME ($TARGET_VERSION_CODE)"
            }
        } catch (e: PackageManager.NameNotFoundException) {
            "PvZ2 TIDAK terinstall — install com.ea.game.pvzfree_row 3.18.0 dulu"
        }
    }

    /**
     * Defensive chmod in case the native lib directory wasn't extracted with
     * the executable bit set for this file. Cheap, safe to call every time.
     */
    fun ensureExecutable(context: Context): Boolean {
        val result = RootShell.exec("chmod 755 '${injectorPath(context)}'")
        return result.exitCode == 0
    }

    fun findPid(processName: String): Int? {
        val result = RootShell.exec("pidof $processName")
        val pid = result.output.trim().split(Regex("\\s+")).firstOrNull()?.toIntOrNull()
        return if (result.exitCode == 0) pid else null
    }

    /** Salin payload ke /data/local/tmp agar proses game bisa dlopen. */
    private fun stagePayload(context: Context): String? {
        val src = payloadPath(context)
        val r = RootShell.exec("cp '$src' '$PAYLOAD_TMP' && chmod 755 '$PAYLOAD_TMP'")
        return if (r.exitCode == 0) PAYLOAD_TMP else null
    }

    fun inject(context: Context, pid: Int): RootShell.Result {
        ensureExecutable(context)
        val staged = stagePayload(context)
        // Fallback: coba path asli bila staging gagal (mis. /data/local/tmp
        // tak bisa ditulis) — injector yang akan membuktikan bisa/tidak.
        val payload = staged ?: payloadPath(context)
        return RootShell.exec("${injectorPath(context)} $pid $payload")
    }
}
