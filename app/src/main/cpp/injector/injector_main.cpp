#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
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
    uint64_t handle = 0;
    std::vector<uint64_t> dlopen_args = {scratch, RTLD_NOW};
    bool called = proc.call(remote_dlopen, dlopen_args, handle);
    proc.detach();

    if (!called) {
        diag("FAIL dlopen call: panggilan dlopen di pid %d tidak selesai", pid);
        if (g_logf) std::fclose(g_logf);
        return EXIT_DLOPEN_CALL;
    }
    if (handle == 0) {
        diag("FAIL dlopen NULL: payload ditolak linker (namespace?) atau file tak terbaca: %s",
             payload_path);
        if (g_logf) std::fclose(g_logf);
        return EXIT_DLOPEN_NULL;
    }

    diag("OK handle=0x%lx", handle);
    std::printf("OK handle=0x%lx\n", handle);
    if (g_logf) std::fclose(g_logf);
    return EXIT_OK;
}
