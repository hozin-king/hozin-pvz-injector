package com.hozinking.pvzinjector

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Logo/status mengambang (TYPE_APPLICATION_OVERLAY) dari aplikasi injector
 * sendiri — ANTI-GAGAL (v1.1).
 *
 * v1.0 hanya menampilkan menu ImGui DI DALAM proses game setelah inject
 * sukses: bila inject gagal, user tidak melihat apa-apa. Overlay ini
 * muncul begitu proses inject dimulai, apa pun hasilnya, dan menampilkan
 * status hidup (menunggu game / menginject / BERHASIL / GAGAL + alasan).
 * Tap = buka aplikasi; ✕ = sembunyikan. Bisa digeser.
 *
 * Ditambahkan via WindowManager konteks aplikasi (bukan Activity) supaya
 * tetap tampil saat user pindah ke game. Tanpa foreground service —
 * window yang sudah ditambahkan bertahan selama proses aplikasi hidup.
 */
object FloatingOverlay {

    // Semua operasi WindowManager HARUS di main thread (ViewRootImpl butuh
    // Looper); alur inject jalan di worker thread, jadi semua dipost ke sini.
    private val mainHandler = Handler(Looper.getMainLooper())

    private var wm: WindowManager? = null
    private var view: View? = null
    private var statusView: TextView? = null
    private var params: WindowManager.LayoutParams? = null

    fun canDrawOverlays(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Settings.canDrawOverlays(context)
        } else {
            true
        }

    /** Buka layar izin "Tampilkan di atas aplikasi lain" (sekali saja). */
    fun requestPermission(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            !Settings.canDrawOverlays(context)
        ) {
            val intent = Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        }
    }

    /** Tampilkan overlay (atau update status bila sudah tampil). */
    fun show(context: Context, initialStatus: String) {
        mainHandler.post { showOnMain(context, initialStatus) }
    }

    private fun showOnMain(context: Context, initialStatus: String) {
        val app = context.applicationContext
        if (view != null) {
            setStatus(initialStatus)
            return
        }
        if (!canDrawOverlays(app)) return
        wm = app.getSystemService(Context.WINDOW_SERVICE) as WindowManager

        val layout = LinearLayout(app).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(28, 20, 16, 20)
            setBackgroundColor(Color.parseColor("#E61B1B2E"))
        }
        val status = TextView(app).apply {
            text = initialStatus
            setTextColor(Color.WHITE)
            textSize = 14f
        }
        val close = TextView(app).apply {
            text = "  ✕"
            setTextColor(Color.parseColor("#FF9E9E"))
            textSize = 18f
            setOnClickListener { hide() }
        }
        layout.addView(status, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        layout.addView(close)

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = 40
            y = 240
        }

        // Geser (drag) + tap (buka aplikasi). Tap dibedakan dari drag
        // lewat jarak gerak — geser kecil (<12px) dianggap tap.
        var downX = 0f
        var downY = 0f
        var startX = 0
        var startY = 0
        var moved = false
        layout.setOnTouchListener { _, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    downX = event.rawX
                    downY = event.rawY
                    startX = params?.x ?: 0
                    startY = params?.y ?: 0
                    moved = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = (event.rawX - downX).toInt()
                    val dy = (event.rawY - downY).toInt()
                    if (kotlin.math.abs(dx) > 12 || kotlin.math.abs(dy) > 12) moved = true
                    if (moved) {
                        params?.x = startX + dx
                        params?.y = startY + dy
                        try {
                            wm?.updateViewLayout(view, params)
                        } catch (_: Exception) {
                        }
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    if (!moved) {
                        val intent = Intent(app, MainActivity::class.java)
                        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        app.startActivity(intent)
                    }
                    true
                }
                else -> false
            }
        }

        statusView = status
        view = layout
        try {
            wm?.addView(layout, params)
        } catch (e: Exception) {
            // Izin dicabut di tengah jalan, dsb. — overlay batal, alur
            // inject tetap jalan; status hanya tampil di aplikasi.
            view = null
            statusView = null
            wm = null
        }
    }

    /** Update teks status (aman dipanggil dari thread mana pun). */
    fun setStatus(text: String) {
        mainHandler.post { statusView?.text = text }
    }

    fun isShown(): Boolean = view != null

    fun hide() {
        mainHandler.post { hideOnMain() }
    }

    private fun hideOnMain() {
        try {
            view?.let { wm?.removeView(it) }
        } catch (_: Exception) {
        }
        view = null
        statusView = null
        params = null
        wm = null
    }
}
