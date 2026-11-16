// payload_main.cpp — Hozin PvZ Injector v1.0 (PvZ2 3.18.0 / 3180).
//
// Arsitektur (dari AUDIT-INJECTOR.md): payload di-dlopen ke proses game
// oleh injector root (ptrace + dlopen, pola RootInjector generik), lalu:
//   1. verifikasi target (package + libpvz.so + BuildID) — GAGAL = keluar
//      diam-diam, tanpa menu, tanpa hook setengah jalan.
//   2. resolve alamat hook: dlsym() nama mangled dulu; bila gagal,
//      pattern-scan (scan.h) sebagai cadangan; bila tetap gagal, fitur
//      itu TIDAK ADA di menu (bukan toggle palsu).
//   3. pasang hook (Dobby) + menu ImGui native di dalam proses game
//      (hook eglSwapBuffers; input dari hook InputConsumer::consume).
//   4. gate mode: hook HANYA berpengaruh di Adventure (LawnApp::
//      IsAdventureMode + cek negatif mode lain). Mode lain / tak dikenali
//      = hook pass-through ke fungsi asli (fail-closed).
//
// YANG TIDAK ADA DI SINI (sengaja): coins/gems/IAP, unlock tanaman via
// store, No Ads, bypass lisensi / Play Integrity / isDeviceRooted, mode
// Arena/ranking. Tanaman kebal + tanpa-cooldown + Plant Food DICORET
// dari v1.0 — fungsi damage tanaman yang persis belum terbukti dari
// simbol; butuh probe runtime sebelum dibuat (bukan ditebak).
//
// Target: com.ea.game.pvzfree_row 3.18.0 (3180), libpvz.so BuildID
// 8e40bdc91b1c112b29b4b4b587a04159. TIDAK menyentuh Java/Dex, Nimble,
// Billing, atau lisensi.

#include "payload.h"

#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <android/input.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "dobby.h"
#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"
#include "scan.h"

#define LOG_TAG "HozinPvZ"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ------------------------------------------------------------------ target

static const char* kTargetPackage = "com.ea.game.pvzfree_row";
static const uint64_t kExpectedLibSize = 50117680ULL;
// BuildID libpvz.so 3.18.0 (20 byte, hex lowercase).
static const char* kExpectedBuildIdHex = "8e40bdc91b1c112b29b4b4b587a04159";

// Nama mangled (salin persis dari REA — .dynsym libpvz.so).
static const char* kSymBoardCtor   = "_ZN5BoardC1EP7LawnApp";
static const char* kSymStartLevel  = "_ZN5Board10StartLevelEv";
static const char* kSymTakeSun     = "_ZN5Board12TakeSunMoneyEi";
static const char* kSymCanTakeSun  = "_ZN5Board15CanTakeSunMoneyEi";
static const char* kSymAddSun      = "_ZN5Board11AddSunMoneyEi";
static const char* kSymPlantCost   = "_ZN5Board19GetCurrentPlantCostE8SeedTypeS0_";
static const char* kSymZombieDmg   = "_ZN6Zombie10TakeDamageEijb";
static const char* kSymSuperMower  = "_ZN5Board17SetSuperMowerModeEb";
static const char* kSymInitMowers  = "_ZN5Board14InitLawnMowersEv";
static const char* kSymIsAdventure = "_ZN7LawnApp15IsAdventureModeEv";
static const char* kSymIsAppLoaded = "_ZN7LawnApp11IsAppLoadedEv";
static const char* kSymIsChallenge = "_ZN7LawnApp15IsChallengeModeEv";
static const char* kSymIsPuzzle    = "_ZN7LawnApp12IsPuzzleModeEv";
static const char* kSymIsSurvival  = "_ZN7LawnApp14IsSurvivalModeEv";
static const char* kSymIsLastStand = "_ZN7LawnApp15IsLastStandModeEv";
static const char* kSymIsIZombie   = "_ZN7LawnApp14IsIZombieLevelEv";
static const char* kSymCanPinata   = "_ZN7LawnApp15CanDoPinataModeEv";

// ------------------------------------------------------------------- types

using BoardCtorFn    = void (*)(void* thiz, void* app);
using StartLevelFn   = void (*)(void* thiz);
using TakeSunFn      = bool (*)(void* thiz, int amount);   // TERBUKTI bool (disassembly)
using CanTakeSunFn   = bool (*)(void* thiz, int amount);
using AddSunFn       = void (*)(void* thiz, int amount);
using PlantCostFn    = int (*)(void* thiz, int seed, int seed2);
using ZombieDmgFn    = void (*)(void* thiz, int dmg, unsigned flags, bool b);
using SuperMowerFn   = void (*)(void* thiz, bool on);
using InitMowersFn   = void (*)(void* thiz);
using LawnAppBoolFn  = bool (*)(void* thiz);
using SwapBuffersFn  = EGLBoolean (*)(EGLDisplay dpy, EGLSurface surface);
using ConsumeFn      = int32_t (*)(void* consumer, void* factory, bool isRaw,
                                   long sequenceId, uint32_t* outPolicyFlags,
                                   void** outEventPtr);

// ------------------------------------------------------------------- state

namespace {

// Toggle fitur — semua default MATI.
std::atomic<bool> g_sun{false};
std::atomic<bool> g_oneHit{false};
std::atomic<bool> g_freePlant{false};
std::atomic<bool> g_superMower{false};

// Instance game yang ditangkap dari hook (ditulis di game thread).
void* g_lawnApp = nullptr;  // LawnApp* (singleton app, stabil)
void* g_board = nullptr;    // Board* level yang sedang berjalan

// Alamat asli (diisi DobbyHook).
BoardCtorFn   g_origBoardCtor   = nullptr;
StartLevelFn  g_origStartLevel  = nullptr;
TakeSunFn     g_origTakeSun     = nullptr;
CanTakeSunFn  g_origCanTakeSun  = nullptr;
AddSunFn      g_origAddSun      = nullptr;
PlantCostFn   g_origPlantCost   = nullptr;
ZombieDmgFn   g_origZombieDmg   = nullptr;
SuperMowerFn  g_origSuperMower  = nullptr;
InitMowersFn  g_origInitMowers  = nullptr;
LawnAppBoolFn g_fnIsAdventure = nullptr;
LawnAppBoolFn g_fnIsAppLoaded = nullptr;
LawnAppBoolFn g_fnIsChallenge = nullptr;
LawnAppBoolFn g_fnIsPuzzle    = nullptr;
LawnAppBoolFn g_fnIsSurvival  = nullptr;
LawnAppBoolFn g_fnIsLastStand = nullptr;
LawnAppBoolFn g_fnIsIZombie   = nullptr;
LawnAppBoolFn g_fnCanPinata   = nullptr;
SwapBuffersFn g_origSwapBuffers = nullptr;
ConsumeFn     g_origConsume     = nullptr;

// Status pemasangan per fitur (untuk menu — tanpa toggle palsu).
bool g_availSun = false;       // TakeSunMoney + CanTakeSunMoney
bool g_availOneHit = false;    // Zombie::TakeDamage
bool g_availFreePlant = false; // GetCurrentPlantCost
bool g_availMower = false;     // InitLawnMowers + SetSuperMowerMode
bool g_availAddSun = false;    // AddSunMoney (tombol tambah sun)
bool g_gateFnsOk = false;      // semua fungsi gate ter-resolve
bool g_menuReady = false;      // ImGui siap dirender
bool g_imguiSetup = false;

// libpvz.so yang ter-load di proses ini.
uintptr_t g_libBase = 0;
uintptr_t g_execBase = 0;
size_t g_execSize = 0;
char g_libPath[512] = {0};

// -------------------------------------------------------------------- gate
//
// SATU fungsi terpusat, fail-closed. Mod hanya berpengaruh bila:
// LawnApp tertangkap + app loaded + IsAdventureMode() true + SEMUA mode
// non-Adventure false. Mode tak dikenali / fungsi gate hilang = TUTUP.

static bool gate_open() {
    if (!g_lawnApp || !g_gateFnsOk) return false;
    if (!g_fnIsAppLoaded(g_lawnApp)) return false;
    if (!g_fnIsAdventure(g_lawnApp)) return false;
    if (g_fnIsChallenge(g_lawnApp)) return false;
    if (g_fnIsPuzzle(g_lawnApp)) return false;
    if (g_fnIsSurvival(g_lawnApp)) return false;
    if (g_fnIsLastStand(g_lawnApp)) return false;
    if (g_fnIsIZombie(g_lawnApp)) return false;
    if (g_fnCanPinata(g_lawnApp)) return false;
    return true;
}

// ------------------------------------------------------- verifikasi target

static int find_libpvz_cb(struct dl_phdr_info* info, size_t /*size*/, void* /*data*/) {
    if (info->dlpi_name && std::strstr(info->dlpi_name, "libpvz.so")) {
        g_libBase = (uintptr_t)info->dlpi_addr;
        for (int i = 0; i < info->dlpi_phnum; i++) {
            const Elf64_Phdr* ph = &info->dlpi_phdr[i];
            if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
                g_execBase = g_libBase + ph->p_vaddr;
                g_execSize = ph->p_memsz;
            }
        }
        return 1;  // stop
    }
    return 0;
}

static bool read_cmdline_package(char* out, size_t out_sz) {
    FILE* f = std::fopen("/proc/self/cmdline", "rb");
    if (!f) return false;
    size_t n = std::fread(out, 1, out_sz - 1, f);
    std::fclose(f);
    out[n] = '\0';
    return n > 0;
}

static bool find_lib_path() {
    FILE* f = std::fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[1024];
    bool ok = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, "libpvz.so")) {
            // format: addr perms offset dev inode path
            char* p = std::strchr(line, '/');
            if (p) {
                size_t len = std::strlen(p);
                while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == ' ')) p[--len] = '\0';
                std::snprintf(g_libPath, sizeof(g_libPath), "%s", p);
                ok = true;
                break;
            }
        }
    }
    std::fclose(f);
    return ok;
}

// Baca .note.gnu.build-id dari file .so di disk, bandingkan dengan yang
// diaudit. Return false bila file tak terbaca / BuildID beda.
static bool check_build_id() {
    if (!g_libPath[0]) return false;
    FILE* f = std::fopen(g_libPath, "rb");
    if (!f) return false;
    uint8_t ehdr[64];
    if (std::fread(ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) { std::fclose(f); return false; }
    if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
        std::fclose(f); return false;
    }
    uint64_t phoff = 0;
    uint16_t phentsize = 0, phnum = 0;
    std::memcpy(&phoff, ehdr + 32, 8);
    std::memcpy(&phentsize, ehdr + 54, 2);
    std::memcpy(&phnum, ehdr + 56, 2);
    bool ok = false;
    for (int i = 0; i < phnum && !ok; i++) {
        uint8_t ph[56];
        std::fseek(f, (long)(phoff + (uint64_t)i * phentsize), SEEK_SET);
        if (std::fread(ph, 1, sizeof(ph), f) != sizeof(ph)) break;
        uint32_t p_type = 0;
        uint64_t p_offset = 0, p_filesz = 0;
        std::memcpy(&p_type, ph + 0, 4);
        std::memcpy(&p_offset, ph + 8, 8);
        std::memcpy(&p_filesz, ph + 32, 8);
        if (p_type != 4 /*PT_NOTE*/) continue;
        uint64_t pos = p_offset, end = p_offset + p_filesz;
        while (pos + 12 <= end) {
            uint8_t nh[12];
            std::fseek(f, (long)pos, SEEK_SET);
            if (std::fread(nh, 1, 12, f) != 12) break;
            uint32_t namesz = 0, descsz = 0, type = 0;
            std::memcpy(&namesz, nh + 0, 4);
            std::memcpy(&descsz, nh + 4, 4);
            std::memcpy(&type, nh + 8, 4);
            uint64_t name_off = pos + 12;
            uint64_t desc_off = name_off + ((namesz + 3) & ~3u);
            if (type == 3 /*NT_GNU_BUILD_ID*/ && namesz == 4 && descsz == 20) {
                uint8_t id[20];
                std::fseek(f, (long)desc_off, SEEK_SET);
                if (std::fread(id, 1, 20, f) == 20) {
                    char hex[41];
                    for (int b = 0; b < 20; b++)
                        std::snprintf(hex + b * 2, 3, "%02x", id[b]);
                    hex[40] = '\0';
                    ok = (std::strcmp(hex, kExpectedBuildIdHex) == 0);
                    LOGI("BuildID libpvz.so: %s (expected %s)", hex, kExpectedBuildIdHex);
                }
                break;
            }
            pos = desc_off + ((descsz + 3) & ~3u);
        }
    }
    std::fclose(f);
    return ok;
}

static bool verify_target() {
    char pkg[256] = {0};
    if (!read_cmdline_package(pkg, sizeof(pkg)) ||
        std::strcmp(pkg, kTargetPackage) != 0) {
        LOGE("package bukan target (%s) — keluar diam-diam", pkg);
        return false;
    }
    // Tunggu libpvz.so termuat (inject bisa terjadi sebelum engine start).
    for (int i = 0; i < 300 && g_libBase == 0; i++) {
        dl_iterate_phdr(find_libpvz_cb, nullptr);
        if (g_libBase == 0) usleep(200 * 1000);
    }
    if (g_libBase == 0 || g_execBase == 0 || g_execSize == 0) {
        LOGE("libpvz.so tidak termuat — keluar diam-diam");
        return false;
    }
    if (!find_lib_path()) {
        LOGE("path libpvz.so tidak ketemu di maps");
        return false;
    }
    struct stat st;
    if (stat(g_libPath, &st) != 0 || (uint64_t)st.st_size != kExpectedLibSize) {
        LOGE("ukuran libpvz.so tidak cocok (%lld) — keluar diam-diam",
             (long long)(st.st_size));
        return false;
    }
    if (!check_build_id()) {
        LOGE("BuildID libpvz.so tidak cocok — keluar diam-diam");
        return false;
    }
    LOGI("target terverifikasi: %s, libpvz.so base=0x%lx exec=0x%lx+%zu",
         pkg, g_libBase, g_execBase, g_execSize);
    return true;
}

// ------------------------------------------------------------- resolver

// dlsym dulu; bila gagal, pattern-scan (cadangan). Return nullptr bila
// keduanya gagal — pemanggil yang memutuskan (fitur hilang, bukan nekat).
static void* resolve_fn(const char* mangled, const char* pattern_name) {
    void* addr = dlsym(RTLD_DEFAULT, mangled);
    if (addr) {
        LOGI("resolve %s via dlsym: %p", pattern_name, addr);
        return addr;
    }
    const PvzPattern* pat = pvz_find_pattern(pattern_name);
    if (pat && g_execBase != 0) {
        addr = pvz_scan_pattern(g_execBase, g_execSize, *pat);
        if (addr) LOGI("resolve %s via pattern-scan: %p", pattern_name, addr);
    }
    if (!addr) LOGE("resolve %s GAGAL (dlsym + pattern)", pattern_name);
    return addr;
}

static bool hook_one(void* addr, void* repl, void** orig_out, const char* name) {
    if (!addr) return false;
    int rc = DobbyHook(addr, repl, orig_out);
    if (rc != 0 || *orig_out == nullptr) {
        LOGE("DobbyHook %s gagal rc=%d", name, rc);
        *orig_out = nullptr;
        return false;
    }
    LOGI("hook %s terpasang @ %p", name, addr);
    return true;
}

// ------------------------------------------------------------- hook game

static void hook_board_ctor(void* thiz, void* app) {
    if (g_origBoardCtor) g_origBoardCtor(thiz, app);
    g_lawnApp = app;  // LawnApp* stabil selama proses hidup
}

static void hook_start_level(void* thiz) {
    g_board = thiz;  // Board* level yang sedang berjalan
    if (g_origStartLevel) g_origStartLevel(thiz);
}

static bool hook_take_sun(void* thiz, int amount) {
    if (g_sun.load() && gate_open()) return true;  // pura-pura berhasil
    return g_origTakeSun ? g_origTakeSun(thiz, amount) : false;
}

static bool hook_can_take_sun(void* thiz, int amount) {
    if (g_sun.load() && gate_open()) return true;
    return g_origCanTakeSun ? g_origCanTakeSun(thiz, amount) : false;
}

static int hook_plant_cost(void* thiz, int seed, int seed2) {
    if (g_freePlant.load() && gate_open()) return 0;
    return g_origPlantCost ? g_origPlantCost(thiz, seed, seed2) : 0;
}

static void hook_zombie_damage(void* thiz, int dmg, unsigned flags, bool b) {
    if (g_origZombieDmg) {
        if (g_oneHit.load() && gate_open())
            g_origZombieDmg(thiz, 100000, flags, b);  // 1-hit
        else
            g_origZombieDmg(thiz, dmg, flags, b);
    }
}

static void hook_init_mowers(void* thiz) {
    if (g_origInitMowers) g_origInitMowers(thiz);
    if (g_superMower.load() && gate_open() && g_origSuperMower)
        g_origSuperMower(thiz, true);
}

// ------------------------------------------------------------- menu ImGui

static void draw_menu() {
    ImGui::SetNextWindowPos(ImVec2(30, 30), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(560, 0), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Hozin PvZ Injector v1.0", nullptr)) {
        ImGui::End();
        return;
    }
    ImGui::Text("PvZ2 3.18.0 (3180) — target terverifikasi");
    bool gate = gate_open();
    if (gate)
        ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.3f, 1.0f),
                           "Mode: ADVENTURE — mod AKTIF");
    else
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                           "Mode: bukan Adventure — mod NONAKTIF");
    if (!g_gateFnsOk)
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
                           "GATE TIDAK TERSEDIA — semua fitur nonaktif");
    ImGui::Separator();

    if (g_availSun) {
        bool v = g_sun.load();
        if (ImGui::Checkbox("Sun tak habis", &v)) g_sun.store(v);
    } else {
        ImGui::TextDisabled("Sun tak habis — tidak tersedia di versi ini");
    }
    if (g_availOneHit) {
        bool v = g_oneHit.load();
        if (ImGui::Checkbox("1-hit kill zombie", &v)) g_oneHit.store(v);
    } else {
        ImGui::TextDisabled("1-hit kill zombie — tidak tersedia di versi ini");
    }
    if (g_availFreePlant) {
        bool v = g_freePlant.load();
        if (ImGui::Checkbox("Tanam gratis (biaya sun 0)", &v)) g_freePlant.store(v);
    } else {
        ImGui::TextDisabled("Tanam gratis — tidak tersedia di versi ini");
    }
    if (g_availMower) {
        bool v = g_superMower.load();
        if (ImGui::Checkbox("Super mower selalu aktif", &v)) g_superMower.store(v);
    } else {
        ImGui::TextDisabled("Super mower — tidak tersedia di versi ini");
    }

    ImGui::Separator();
    if (g_availAddSun) {
        if (ImGui::Button("Tambah Sun +5000")) {
            if (gate && g_board && g_origAddSun) g_origAddSun(g_board, 5000);
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(hanya saat level Adventure berjalan)");
    }
    if (ImGui::Button("Matikan semua")) {
        g_sun.store(false);
        g_oneHit.store(false);
        g_freePlant.store(false);
        g_superMower.store(false);
    }
    ImGui::Separator();
    ImGui::TextWrapped("Solo/offline saja. Sentuhan pada menu juga diteruskan "
                       "ke game — pause dulu sebelum ubah toggle. v1.0 tanpa "
                       "tanaman kebal / tanpa-cooldown (belum terbukti, "
                       "butuh probe runtime).");
    ImGui::End();
}

static void setup_imgui(int w, int h) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2((float)w, (float)h);
    ImGui_ImplOpenGL3_Init("#version 100");
    ImFontConfig font_cfg;
    font_cfg.SizePixels = 22.0f;
    io.Fonts->AddFontDefault(&font_cfg);
    ImGui::GetStyle().ScaleAllSizes(2.5f);
    g_imguiSetup = true;
}

static EGLBoolean hook_egl_swap_buffers(EGLDisplay dpy, EGLSurface surface) {
    if (g_menuReady) {
        EGLint w = 0, h = 0;
        eglQuerySurface(dpy, surface, EGL_WIDTH, &w);
        eglQuerySurface(dpy, surface, EGL_HEIGHT, &h);
        if (w > 0 && h > 0) {
            if (!g_imguiSetup) setup_imgui(w, h);
            ImGui_ImplAndroid_NewFrame(w, h);
            ImGui_ImplOpenGL3_NewFrame();
            ImGui::NewFrame();
            draw_menu();
            ImGui::EndFrame();
            ImGui::Render();
            glViewport(0, 0, w, h);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        }
    }
    return g_origSwapBuffers ? g_origSwapBuffers(dpy, surface)
                             : EGL_TRUE;
}

// ------------------------------------------------------------- input hook
//
// Umpan sentuhan game ke ImGui lewat hook InputConsumer::consume
// (Android 15+ 64-bit). Event TETAP diteruskan ke game (pass-through,
// tanpa swallow) — menelan event berisiko merusak antrean input; lihat
// catatan di menu ("pause dulu sebelum ubah toggle").

static int32_t hook_consume(void* consumer, void* factory, bool isRaw,
                            long sequenceId, uint32_t* outPolicyFlags,
                            void** outEventPtr) {
    int32_t r = g_origConsume
        ? g_origConsume(consumer, factory, isRaw, sequenceId, outPolicyFlags,
                        outEventPtr)
        : -11;  // WOULD_BLOCK
    if (r == 0 && outEventPtr && *outEventPtr && g_imguiSetup)
        ImGui_ImplAndroid_HandleInputEvent((AInputEvent*)*outEventPtr);
    return r;
}

// Fallback pra-Android 15 (best-effort; simbol lama). Event yang terisi
// adalah parameter ke-2; `thiz` diteruskan seperti pola template.
static void (*g_origInputOld)(void* thiz, void* motion_event, void* msg) = nullptr;
static void hook_input_old(void* thiz, void* motion_event, void* msg) {
    if (g_origInputOld) g_origInputOld(thiz, motion_event, msg);
    if (g_imguiSetup)
        ImGui_ImplAndroid_HandleInputEvent((AInputEvent*)motion_event);
}

static void install_input_hook() {
    void* libinput = dlopen("/system/lib64/libinput.so", RTLD_NOW | RTLD_LOCAL);
    if (!libinput) libinput = dlopen("/system/lib/libinput.so", RTLD_NOW | RTLD_LOCAL);
    if (!libinput) {
        LOGI("input hook: libinput.so tidak bisa dibuka — menu render saja");
        return;
    }
    void* sym = dlsym(libinput,
        "_ZN7android13InputConsumer7consumeEPNS_26InputEventFactoryInterfaceEblPjPPNS_10InputEventE");
    if (sym) {
        int rc = DobbyHook(sym, (void*)hook_consume, (void**)&g_origConsume);
        if (rc == 0 && g_origConsume) {
            LOGI("input hook terpasang (InputConsumer::consume)");
            return;
        }
        LOGE("input hook consume gagal rc=%d", rc);
    }
    void* sym_old = dlsym(libinput,
        "_ZN7android13InputConsumer21initializeMotionEventEPNS_11MotionEventEPKNS_12InputMessageE");
    if (sym_old) {
        int rc = DobbyHook(sym_old, (void*)hook_input_old, (void**)&g_origInputOld);
        if (rc == 0 && g_origInputOld) {
            LOGI("input hook terpasang (initializeMotionEvent, fallback)");
            return;
        }
    }
    LOGI("input hook tidak tersedia — menu render, sentuhan mungkin tak jalan");
}

// ------------------------------------------------------------------- init

static void* init_thread(void*) {
    if (!verify_target()) return nullptr;

    // --- resolve gate dulu: tanpa gate, fitur TIDAK BOLEH hidup ---
    g_fnIsAdventure = (LawnAppBoolFn)resolve_fn(kSymIsAdventure, "IsAdventureMode");
    g_fnIsAppLoaded = (LawnAppBoolFn)resolve_fn(kSymIsAppLoaded, "IsAppLoaded");
    g_fnIsChallenge = (LawnAppBoolFn)resolve_fn(kSymIsChallenge, "IsChallengeMode");
    g_fnIsPuzzle    = (LawnAppBoolFn)resolve_fn(kSymIsPuzzle, "IsPuzzleMode");
    g_fnIsSurvival  = (LawnAppBoolFn)resolve_fn(kSymIsSurvival, "IsSurvivalMode");
    g_fnIsLastStand = (LawnAppBoolFn)resolve_fn(kSymIsLastStand, "IsLastStandMode");
    g_fnIsIZombie   = (LawnAppBoolFn)resolve_fn(kSymIsIZombie, "IsIZombieLevel");
    g_fnCanPinata   = (LawnAppBoolFn)resolve_fn(kSymCanPinata, "CanDoPinataMode");
    g_gateFnsOk = g_fnIsAdventure && g_fnIsAppLoaded && g_fnIsChallenge &&
                  g_fnIsPuzzle && g_fnIsSurvival && g_fnIsLastStand &&
                  g_fnIsIZombie && g_fnCanPinata;
    if (!g_gateFnsOk)
        LOGE("fungsi gate tidak lengkap — mod nonaktif permanen (menu status saja)");

    // --- resolve + hook fitur (per fitur; yang gagal = hilang dari menu) ---
    void* a = resolve_fn(kSymTakeSun, "TakeSunMoney");
    void* b = resolve_fn(kSymCanTakeSun, "CanTakeSunMoney");
    if (g_gateFnsOk && a && b) {
        void* o1 = nullptr; void* o2 = nullptr;
        bool h1 = hook_one(a, (void*)hook_take_sun, &o1, "TakeSunMoney");
        bool h2 = hook_one(b, (void*)hook_can_take_sun, &o2, "CanTakeSunMoney");
        if (h1 && h2) {
            g_origTakeSun = (TakeSunFn)o1;
            g_origCanTakeSun = (CanTakeSunFn)o2;
            g_availSun = true;
        }
    }
    a = resolve_fn(kSymZombieDmg, "ZombieTakeDamage");
    if (g_gateFnsOk && a) {
        void* o = nullptr;
        if (hook_one(a, (void*)hook_zombie_damage, &o, "Zombie::TakeDamage")) {
            g_origZombieDmg = (ZombieDmgFn)o;
            g_availOneHit = true;
        }
    }
    a = resolve_fn(kSymPlantCost, "GetCurrentPlantCost");
    if (g_gateFnsOk && a) {
        void* o = nullptr;
        if (hook_one(a, (void*)hook_plant_cost, &o, "GetCurrentPlantCost")) {
            g_origPlantCost = (PlantCostFn)o;
            g_availFreePlant = true;
        }
    }
    a = resolve_fn(kSymInitMowers, "InitLawnMowers");
    b = resolve_fn(kSymSuperMower, "SetSuperMowerMode");
    if (g_gateFnsOk && a && b) {
        g_origSuperMower = (SuperMowerFn)b;  // dipanggil, bukan di-hook
        void* o = nullptr;
        if (hook_one(a, (void*)hook_init_mowers, &o, "InitLawnMowers")) {
            g_origInitMowers = (InitMowersFn)o;
            g_availMower = true;
        }
    }
    a = resolve_fn(kSymAddSun, "AddSunMoney");
    if (a) g_origAddSun = (AddSunFn)a, g_availAddSun = true;

    // --- tangkap instance: Board ctor (LawnApp*) + StartLevel (Board*) ---
    a = resolve_fn(kSymBoardCtor, "BoardCtor");
    if (a) {
        void* o = nullptr;
        if (hook_one(a, (void*)hook_board_ctor, &o, "Board::Board"))
            g_origBoardCtor = (BoardCtorFn)o;
    }
    a = resolve_fn(kSymStartLevel, "StartLevel");
    if (a) {
        void* o = nullptr;
        if (hook_one(a, (void*)hook_start_level, &o, "Board::StartLevel"))
            g_origStartLevel = (StartLevelFn)o;
    }

    // --- render + input (menu). Gagal di sini = tanpa menu, fitur tetap
    // jalan lewat toggle terakhir (default MATI = aman).
    void* swap = dlsym(RTLD_DEFAULT, "eglSwapBuffers");
    if (!swap) swap = dlsym(RTLD_NEXT, "eglSwapBuffers");
    if (swap) {
        void* o = nullptr;
        if (hook_one(swap, (void*)hook_egl_swap_buffers, &o, "eglSwapBuffers")) {
            g_origSwapBuffers = (SwapBuffersFn)o;
            g_menuReady = true;
        }
    } else {
        LOGE("eglSwapBuffers tidak ketemu — menu tidak akan tampil");
    }
    install_input_hook();

    LOGI("payload siap: sun=%d 1hit=%d freeplant=%d mower=%d addsun=%d gate=%d menu=%d",
         g_availSun, g_availOneHit, g_availFreePlant, g_availMower,
         g_availAddSun, g_gateFnsOk, g_menuReady);
    return nullptr;
}

}  // namespace

void payload_init() {
    LOGI("payload_init: Hozin PvZ Injector v1.0 masuk ke proses target");
    pthread_t t;
    if (pthread_create(&t, nullptr, init_thread, nullptr) == 0)
        pthread_detach(t);
    else
        LOGE("init thread gagal dibuat");
}

__attribute__((constructor)) static void on_load() {
    payload_init();
}
