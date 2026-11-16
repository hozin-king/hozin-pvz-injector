#include <android/dlext.h>
#include <android/log.h>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "proc_maps.h"
#include "remote_call_arm64.h"

#define LOG_TAG "RootInjector"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Exit code bermakna (v1.1) — aplikasi memetakan ini ke alasan yang bisa
// dibaca manusia di layar diagnosis. 0 = sukses.
enum : int {
    EXIT_OK = 0,
    EXIT_USAGE = 2,         // argumen salah (bug aplikasi)
    EXIT_LOCAL_MODULE = 3,  // libdl/libc tak ketemu di proses injector
    EXIT_ATTACH = 4,        // ptrace attach ditolak
    EXIT_REMOTE_RESOLVE = 5,  // libc/libdl tak ketemu di proses game
    EXIT_REMOTE_MMAP = 6,   // alokasi memori di game gagal
    EXIT_WRITE_MEM = 7,     // tulis path payload ke game gagal
    EXIT_DLOPEN_CALL = 8,   // panggilan dlopen tak selesai
    EXIT_DLOPEN_NULL = 9,   // dlopen kembalikan NULL (linker namespace / file)
};

// Log diagnosis v1.1 — v1.0 hanya LOGE ke logcat, sedangkan RootShell
// hanya menangkap stdout: semua kegagalan hilang tanpa jejak ("output="
// kosong). Sekarang tiap langkah ditulis ke stdout (ditangkap aplikasi)
// DAN ke file log (cadangan bila stdout hilang).
static const char* kInjectLogPath = "/data/local/tmp/hozinpvz_inject.log";
static FILE* g_logf = nullptr;

static void diag(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::printf("%s\n", buf);
    std::fflush(stdout);
    if (g_logf) {
        std::fprintf(g_logf, "%s\n", buf);
        std::fflush(g_logf);
    }
}

namespace {

// Offset of fn inside whatever currently maps lib_name in THIS process.
// Resolving the remote address the same way (lowest-base mapping whose path
// contains lib_name, plus this offset) only works because the library file
// on disk is identical for both processes -- ASLR only moves the base, not
// internal offsets.
bool local_offset(const char* lib_name, void* fn, uintptr_t& offset_out) {
    injector::ModuleInfo mod{};
    if (!injector::find_module(0, lib_name, mod)) {
        LOGE("could not find local module %s", lib_name);
        return false;
    }
    offset_out = reinterpret_cast<uintptr_t>(fn) - mod.base;
    return true;
}

bool resolve_remote(int pid, const char* lib_name, uintptr_t offset, uintptr_t& addr_out) {
    injector::ModuleInfo mod{};
    if (!injector::find_module(pid, lib_name, mod)) {
        LOGE("could not find remote module %s in pid %d", lib_name, pid);
        return false;
    }
    addr_out = mod.base + offset;
    return true;
}

// Baca string C dari memori proses target (hasil dlerror()). Satu pread
// 512 byte; cukup untuk pesan linker yang biasanya < 200 karakter.
bool read_remote_cstr(injector::RemoteProcess& proc, uint64_t addr, std::string& out) {
    if (addr == 0) return false;
    char buf[512];
    if (!proc.read_mem(addr, buf, sizeof(buf))) return false;
    buf[sizeof(buf) - 1] = '\0';
    out = buf;
    return true;
}

// Panggil dlerror() di dalam proses target dan tulis pesan LENGKAPNYA ke
// diagnosis. Inilah yang hilang di v1.1 ("namespace?" hanya tebakan):
// "library X not found" vs "Permission denied" membedakan akar dengan
// pasti. Mengembalikan false bila dlerror tak tersedia / tak ada pesan.
bool capture_dlerror(injector::RemoteProcess& proc, uintptr_t remote_dlerror,
                     const char* tag) {
    if (remote_dlerror == 0) {
        diag("%s: dlerror tak tersedia di proses game", tag);
        return false;
    }
    uint64_t err_ptr = 0;
    std::vector<uint64_t> no_args;
    if (!proc.call(remote_dlerror, no_args, err_ptr)) {
        diag("%s: panggilan dlerror tidak selesai", tag);
        return false;
    }
    if (err_ptr == 0) {
        diag("%s: dlerror kosong (linker tak mencatat error)", tag);
        return false;
    }
    std::string msg;
    if (!read_remote_cstr(proc, err_ptr, msg) || msg.empty()) {
        diag("%s: dlerror tak terbaca dari memori game", tag);
        return false;
    }
    diag("%s: %s", tag, msg.c_str());
    return true;
}

// TR-port (v1.3): cek apakah payload sudah ter-map di proses target.
// dlopen percobaan sebelumnya bisa selesai TERLAMBAT, setelah timeout —
// tanpa cek ini, retry = dlopen kedua = constructor kedua = crash.
bool is_payload_loaded(int pid) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return false;
    char line[1024];
    bool found = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strstr(line, "payload.so")) { found = true; break; }
    }
    std::fclose(f);
    return found;
}

// TR-port (v1.3): verifikasi alamat remote berada di mapping executable
// milik modul yang diharapkan SEBELUM dipanggil — jangan panggil alamat
// sampah. (Pelajaran TR: dlopen hidup di libdl.so, BUKAN libc.so —
// mencampur modul = alamat salah = SIGSEGV di PC yang dipanggil.)
bool verify_xmap(int pid, uintptr_t addr, const char* lib_name) {
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = std::fopen(path, "r");
    if (!f) return false;
    char line[1024];
    bool ok = false;
    while (std::fgets(line, sizeof(line), f)) {
        uintptr_t s = 0, e = 0;
        char perms[5] = {0};
        char pbuf[512] = {0};
        int n = std::sscanf(line, "%lx-%lx %4s %*s %*s %*d %511s",
                            &s, &e, perms, pbuf);
        if (n < 4 || pbuf[0] == '\0') continue;
        if (s <= addr && addr < e) {
            ok = (std::strchr(perms, 'x') != nullptr) &&
                 (std::strstr(pbuf, lib_name) != nullptr);
            diag("verify dlopen: %s %s (%s): %s", pbuf, perms, lib_name,
                 ok ? "OK" : "SALAH");
            break;
        }
    }
    std::fclose(f);
    return ok;
}

// Pilih thread target LAIN yang sedang TIDUR (v1.3). Thread yang tidur
// di futex/epoll hampir pasti tidak memegang loader lock, jadi remote
// call dari sana jauh lebih aman daripada dari main thread yang barusan
// hang. Main thread (tid == pid) tidak pernah dipilih ulang. Return
// false bila tidak ada kandidat.
bool pick_sleepy_thread(int pid, int exclude_tid, int& tid_out, std::string& wchan_out) {
    char task_dir[64];
    std::snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);
    DIR* d = opendir(task_dir);
    if (!d) return false;
    int best_tid = -1, best_score = -1;
    std::string best_wchan;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        int tid = std::atoi(e->d_name);
        if (tid == exclude_tid || tid == pid) continue;
        char stat_path[96];
        std::snprintf(stat_path, sizeof(stat_path), "/proc/%d/task/%d/stat", pid, tid);
        FILE* f = std::fopen(stat_path, "r");
        if (!f) continue;
        char buf[1024];
        size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
        std::fclose(f);
        if (n == 0) continue;
        buf[n] = '\0';
        // state = field ke-3, tepat setelah ')' terakhir dari comm.
        char* rp = std::strrchr(buf, ')');
        if (!rp || rp[1] == '\0') continue;
        char state = rp[2];
        if (state != 'S' && state != 'T') continue;
        char wchan_path[96];
        std::snprintf(wchan_path, sizeof(wchan_path), "/proc/%d/task/%d/wchan", pid, tid);
        std::string wchan;
        FILE* wf = std::fopen(wchan_path, "r");
        if (wf) {
            char wb[128];
            if (std::fgets(wb, sizeof(wb), wf)) wchan = wb;
            std::fclose(wf);
        }
        int score = 0;
        if (wchan.find("futex") != std::string::npos) score = 3;
        else if (wchan.find("epoll") != std::string::npos) score = 3;
        else if (wchan.find("poll") != std::string::npos) score = 2;
        else if (state == 'S') score = 1;
        if (score > best_score) {
            best_score = score;
            best_tid = tid;
            best_wchan = wchan.empty() ? "?" : wchan;
        }
    }
    closedir(d);
    if (best_tid < 0) return false;
    tid_out = best_tid;
    wchan_out = best_wchan;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    g_logf = std::fopen(kInjectLogPath, "w");
    if (argc != 3) {
        diag("usage: injector <pid> <payload.so path>");
        if (g_logf) std::fclose(g_logf);
        return EXIT_USAGE;
    }

    int pid = std::atoi(argv[1]);
    const char* payload_path = argv[2];
    if (pid <= 0 || std::strlen(payload_path) >= 0x1000) {
        diag("bad pid or payload path too long (pid=%d)", pid);
        if (g_logf) std::fclose(g_logf);
        return EXIT_USAGE;
    }
    diag("inject start: pid=%d payload=%s", pid, payload_path);

    uintptr_t dlopen_offset = 0;
    uintptr_t mmap_offset = 0;
    if (!local_offset("libdl.so", reinterpret_cast<void*>(&dlopen), dlopen_offset)) {
        diag("FAIL local: libdl.so/dlopen tidak ketemu di proses injector");
        if (g_logf) std::fclose(g_logf);
        return EXIT_LOCAL_MODULE;
    }
    if (!local_offset("libc.so", reinterpret_cast<void*>(&mmap), mmap_offset)) {
        diag("FAIL local: libc.so/mmap tidak ketemu di proses injector");
        if (g_logf) std::fclose(g_logf);
        return EXIT_LOCAL_MODULE;
    }
    diag("local offsets: dlopen=0x%lx mmap=0x%lx", dlopen_offset, mmap_offset);

    injector::RemoteProcess proc;
    if (!proc.attach(pid)) {
        diag("FAIL attach: ptrace ke pid %d ditolak (root tidak aktif? SELinux?)", pid);
        if (g_logf) std::fclose(g_logf);
        return EXIT_ATTACH;
    }
    diag("ptrace attach OK pid=%d", pid);

    uintptr_t remote_mmap = 0, remote_dlopen = 0;
    if (!resolve_remote(pid, "libc.so", mmap_offset, remote_mmap) ||
        !resolve_remote(pid, "libdl.so", dlopen_offset, remote_dlopen)) {
        diag("FAIL resolve: libc/libdl tidak ketemu di maps pid %d (layout aneh?)", pid);
        proc.detach();
        if (g_logf) std::fclose(g_logf);
        return EXIT_REMOTE_RESOLVE;
    }
    diag("remote mmap=0x%lx remote dlopen=0x%lx", remote_mmap, remote_dlopen);

    // TR-port (v1.3): jangan panggil alamat dlopen yang tidak di mapping
    // executable libdl.so — batal sebelum target disentuh lebih jauh.
    if (!verify_xmap(pid, remote_dlopen, "libdl.so")) {
        diag("FAIL verify: alamat dlopen tidak di mapping x-perm libdl.so — batal");
        proc.detach();
        if (g_logf) std::fclose(g_logf);
        return EXIT_REMOTE_RESOLVE;
    }

    // Alamat remote tambahan untuk diagnosis + fallback (v1.2). Semuanya
    // LENIENT: bila tak ketemu, jalurnya dilewati dengan catatan — jangan
    // sampai ketiadaan fallback membunuh jalur utama.
    uintptr_t remote_dlerror = 0, remote_dlopen_ext = 0, remote_open = 0;
    uintptr_t dlerror_offset = 0, dlopen_ext_offset = 0, open_offset = 0;
    if (local_offset("libdl.so", reinterpret_cast<void*>(&dlerror), dlerror_offset) &&
        resolve_remote(pid, "libdl.so", dlerror_offset, remote_dlerror)) {
        diag("remote dlerror=0x%lx", remote_dlerror);
    } else {
        diag("catatan: dlerror tak ter-resolve — alasan dlopen gagal tak bisa ditangkap");
    }
    if (local_offset("libdl.so", reinterpret_cast<void*>(&android_dlopen_ext),
                     dlopen_ext_offset) &&
        resolve_remote(pid, "libdl.so", dlopen_ext_offset, remote_dlopen_ext)) {
        diag("remote android_dlopen_ext=0x%lx", remote_dlopen_ext);
    } else {
        diag("catatan: android_dlopen_ext tak ter-resolve — fallback fd tidak tersedia");
    }
    if (local_offset("libc.so",
                     reinterpret_cast<void*>(static_cast<int (*)(const char*, int, ...)>(&open)),
                     open_offset) &&
        resolve_remote(pid, "libc.so", open_offset, remote_open)) {
        diag("remote open=0x%lx", remote_open);
    } else {
        diag("catatan: open tak ter-resolve — fallback fd tidak tersedia");
    }

    // 1) allocate RW scratch in the target for the payload path string.
    uint64_t scratch = 0;
    std::vector<uint64_t> mmap_args = {
        0,                                     // addr
        0x1000,                                // length
        PROT_READ | PROT_WRITE,                // prot
        MAP_ANONYMOUS | MAP_PRIVATE,            // flags
        static_cast<uint64_t>(-1),              // fd
        0                                        // offset
    };
    if (!proc.call(remote_mmap, mmap_args, scratch) || scratch == 0 ||
        scratch == static_cast<uint64_t>(-1)) {
        diag("FAIL remote mmap: alokasi scratch di pid %d gagal", pid);
        proc.detach();
        if (g_logf) std::fclose(g_logf);
        return EXIT_REMOTE_MMAP;
    }
    diag("remote scratch=0x%lx", scratch);

    // 2) write the payload path into that scratch region.
    size_t path_len = std::strlen(payload_path) + 1;
    if (!proc.write_mem(scratch, payload_path, path_len)) {
        diag("FAIL write: path payload tidak bisa ditulis ke 0x%lx", scratch);
        proc.detach();
        if (g_logf) std::fclose(g_logf);
        return EXIT_WRITE_MEM;
    }
    diag("payload path tertulis (%zu byte)", path_len);

    // 3) call dlopen(scratch, RTLD_NOW) in the target.
    // v1.3: timeout 10 dtk + retry SEKALI di thread lain yang sedang
    // tidur. v1.2 hang ~2 dtk di main thread (exit=8) sementara game
    // tetap hidup — main thread kemungkinan berebut loader lock dengan
    // thread lain; dlopen dari thread tidur jauh lebih aman.
    uint64_t handle = 0;
    std::vector<uint64_t> dlopen_args = {scratch, RTLD_NOW};
    bool called = proc.call(remote_dlopen, dlopen_args, handle, 10000);
    if (!called) {
        diag("dlopen timeout 10 dtk di thread %d — detach bersih, cek maps dulu",
             proc.attached_tid());
        proc.detach();
        // TR-port: dlopen sebelumnya bisa selesai terlambat — bila payload
        // sudah ter-map, JANGAN retry (dlopen kedua = crash).
        if (is_payload_loaded(pid)) {
            diag("payload ter-load (dlopen selesai terlambat) — lanjut tunggu status");
            if (g_logf) std::fclose(g_logf);
            return EXIT_OK;
        }
        int tid2 = -1;
        std::string wchan2;
        if (pick_sleepy_thread(pid, pid, tid2, wchan2) &&
            proc.attach_tid(pid, tid2)) {
            diag("retry dlopen di thread %d (wchan=%s)", tid2, wchan2.c_str());
            called = proc.call(remote_dlopen, dlopen_args, handle, 10000);
            if (!called) {
                diag("retry dlopen juga timeout di thread %d", tid2);
            }
        } else {
            diag("tidak ada thread tidur lain untuk retry — lanjut ke diagnosis dlerror/fallback");
        }
    }

    if (!called) {
        diag("FAIL dlopen call: panggilan dlopen di pid %d tidak selesai", pid);
        proc.detach();
        diag("game masih jalan setelah inject: %s",
             (kill(pid, 0) == 0) ? "ya" : "TIDAK - game mati");
        if (g_logf) std::fclose(g_logf);
        return EXIT_DLOPEN_CALL;
    }
    if (handle != 0) {
        diag("OK handle=0x%lx", handle);
        proc.detach();
        diag("game masih jalan setelah inject: %s",
             (kill(pid, 0) == 0) ? "ya" : "TIDAK - game mati");
        if (g_logf) std::fclose(g_logf);
        return EXIT_OK;
    }

    // dlopen by-path mengembalikan NULL — v1.1 berhenti di sini dengan
    // tebakan ("namespace?"). v1.2: tangkap dlerror() dulu (alasan linker
    // yang sebenarnya), lalu coba fallback android_dlopen_ext via file
    // descriptor: fd dibuka OLEH proses game sendiri (remote open), jadi
    // pemeriksaan path / namespace linker dilewati.
    diag("dlopen by-path NULL — tangkap dlerror:");
    capture_dlerror(proc, remote_dlerror, "dlerror");

    bool ext_ok = false;
    uint64_t handle2 = 0;
    if (remote_dlopen_ext != 0 && remote_open != 0) {
        uint64_t fd = 0;
        std::vector<uint64_t> open_args = {scratch, O_RDONLY, 0};
        bool opened = proc.call(remote_open, open_args, fd);
        if (!opened || static_cast<int64_t>(fd) < 0) {
            diag("fallback fd: remote open(%s) gagal (fd=%lld) — file tak bisa dibuka proses game",
                 payload_path, static_cast<long long>(fd));
        } else {
            diag("fallback fd: remote open OK fd=%llu",
                 static_cast<unsigned long long>(fd));
            android_dlextinfo info{};
            info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
            info.library_fd = static_cast<int>(fd);
            info.library_fd_offset = 0;
            // Scratch: path di [0x0, 0x800), dlextinfo di 0x800.
            if (!proc.write_mem(scratch + 0x800, &info, sizeof(info))) {
                diag("fallback fd: tulis dlextinfo ke scratch gagal");
            } else {
                std::vector<uint64_t> ext_args = {scratch, RTLD_NOW, scratch + 0x800};
                bool called2 = proc.call(remote_dlopen_ext, ext_args, handle2);
                if (!called2) {
                    diag("fallback fd: panggilan android_dlopen_ext tidak selesai");
                } else if (handle2 != 0) {
                    diag("OK handle=0x%lx via android_dlopen_ext (fd)", handle2);
                    ext_ok = true;
                } else {
                    diag("android_dlopen_ext juga NULL — tangkap dlerror:");
                    capture_dlerror(proc, remote_dlerror, "dlerror (ext)");
                }
            }
        }
    } else {
        diag("fallback fd dilewati — android_dlopen_ext/open tak ter-resolve");
    }
    proc.detach();

    bool alive = (kill(pid, 0) == 0);
    diag("game masih jalan setelah inject: %s", alive ? "ya" : "TIDAK - game mati");
    if (ext_ok) {
        if (g_logf) std::fclose(g_logf);
        return EXIT_OK;
    }
    diag("FAIL dlopen NULL: payload ditolak linker / file tak terbaca: %s (lihat baris dlerror di atas)",
         payload_path);
    if (g_logf) std::fclose(g_logf);
    return EXIT_DLOPEN_NULL;
}
