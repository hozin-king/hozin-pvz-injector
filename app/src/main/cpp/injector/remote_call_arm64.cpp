#include "remote_call_arm64.h"

#include <android/log.h>
#include <asm/ptrace.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_TAG "RootInjector"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

namespace injector {

namespace {
constexpr int kDefaultCallTimeoutMs = 2000;  // syscall cepat (mmap/open/dlerror)
constexpr int kWaitRetryUsec = 10000;
constexpr uint32_t kBrk0 = 0xD4200000;  // "brk #0" on arm64
}  // namespace

bool RemoteProcess::attach(pid_t pid) {
    return attach_tid(pid, pid);
}

bool RemoteProcess::attach_tid(pid_t pid, pid_t tid) {
    if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) != 0) {
        LOGE("PTRACE_ATTACH failed for tid %d: %s", tid, std::strerror(errno));
        return false;
    }

    int status = 0;
    if (waitpid(tid, &status, 0) < 0 || !WIFSTOPPED(status)) {
        LOGE("waitpid after attach failed for tid %d", tid);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        return false;
    }

    if (mem_fd_ < 0) {
        char mem_path[32];
        std::snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
        mem_fd_ = open(mem_path, O_RDWR);
        if (mem_fd_ < 0) {
            LOGE("open %s failed: %s", mem_path, std::strerror(errno));
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
            return false;
        }
    }

    pid_ = pid;
    tid_ = tid;
    attached_ = true;
    return true;
}

bool RemoteProcess::detach() {
    if (!attached_) {
        return true;
    }
    if (mem_fd_ >= 0) {
        close(mem_fd_);
        mem_fd_ = -1;
    }
    bool ok = ptrace(PTRACE_DETACH, tid_, nullptr, nullptr) == 0;
    attached_ = false;
    return ok;
}

bool RemoteProcess::interrupt_and_stop() {
    if (ptrace(PTRACE_INTERRUPT, tid_, nullptr, nullptr) != 0) {
        return false;
    }
    for (int i = 0; i < 200; i++) {
        int status = 0;
        pid_t w = waitpid(tid_, &status, WNOHANG);
        if (w == tid_ && WIFSTOPPED(status)) return true;
        if (w < 0) return false;
        usleep(10000);
    }
    return false;
}

bool RemoteProcess::read_mem(uintptr_t addr, void* buf, size_t len) const {
    ssize_t n = pread(mem_fd_, buf, len, static_cast<off_t>(addr));
    return n == static_cast<ssize_t>(len);
}

bool RemoteProcess::write_mem(uintptr_t addr, const void* buf, size_t len) const {
    ssize_t n = pwrite(mem_fd_, buf, len, static_cast<off_t>(addr));
    return n == static_cast<ssize_t>(len);
}

bool RemoteProcess::call(uintptr_t func_addr, const std::vector<uint64_t>& args, uint64_t& result) {
    return call(func_addr, args, result, kDefaultCallTimeoutMs);
}

bool RemoteProcess::call(uintptr_t func_addr, const std::vector<uint64_t>& args,
                         uint64_t& result, int timeout_ms) {
    if (!attached_ || args.size() > 8) {
        return false;
    }

    struct user_pt_regs saved_regs {};
    struct iovec iov{&saved_regs, sizeof(saved_regs)};
    if (ptrace(PTRACE_GETREGSET, tid_, reinterpret_cast<void*>(NT_PRSTATUS), &iov) != 0) {
        LOGE("PTRACE_GETREGSET failed: %s", std::strerror(errno));
        return false;
    }

    struct user_pt_regs work_regs = saved_regs;
    for (size_t i = 0; i < args.size(); ++i) {
        work_regs.regs[i] = args[i];
    }

    uintptr_t return_marker = saved_regs.pc;
    work_regs.pc = func_addr;
    work_regs.regs[30] = return_marker;      // x30 / LR
    work_regs.sp = saved_regs.sp & ~0xFULL;  // AAPCS64 16-byte alignment

    uint32_t original_insn = 0;
    if (!read_mem(return_marker, &original_insn, sizeof(original_insn))) {
        LOGE("failed to read original instruction at return marker 0x%lx", return_marker);
        return false;
    }
    if (!write_mem(return_marker, &kBrk0, sizeof(kBrk0))) {
        LOGE("failed to plant breakpoint at 0x%lx", return_marker);
        return false;
    }

    struct iovec set_iov{&work_regs, sizeof(work_regs)};
    if (ptrace(PTRACE_SETREGSET, tid_, reinterpret_cast<void*>(NT_PRSTATUS), &set_iov) != 0) {
        LOGE("PTRACE_SETREGSET failed: %s", std::strerror(errno));
        write_mem(return_marker, &original_insn, sizeof(original_insn));
        return false;
    }

    // Tunggu breakpoint kembali, DENGAN BATAS WAKTU (v1.3). v1.2: budget
    // tetap ~2 dtk — dlopen payload 1,5 MB di main thread yang sibuk bisa
    // lebih lama dari itu, atau hang berebut loader lock. Timeout di sini
    // BUKAN akhir: pemanggil detach lalu retry di thread lain.
    struct timespec deadline {};
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }

    bool hit = false;
    bool timed_out = false;
    while (!hit) {
        if (ptrace(PTRACE_CONT, tid_, nullptr, nullptr) != 0) {
            LOGE("PTRACE_CONT failed: %s", std::strerror(errno));
            break;
        }
        int status = 0;
        pid_t w = waitpid(tid_, &status, WNOHANG);
        if (w == 0) {
            struct timespec now {};
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                timed_out = true;
                break;
            }
            usleep(kWaitRetryUsec);
            continue;
        }
        if (w < 0) {
            break;
        }
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            struct user_pt_regs check_regs {};
            struct iovec check_iov{&check_regs, sizeof(check_regs)};
            ptrace(PTRACE_GETREGSET, tid_, reinterpret_cast<void*>(NT_PRSTATUS), &check_iov);
            // arm64 leaves pc pointing at the brk instruction itself on trap.
            if (check_regs.pc == return_marker) {
                hit = true;
                result = check_regs.regs[0];
                break;
            }
        }
        // Stop karena sinyal lain: loop lagi (CONT berikutnya meneruskan
        // thread; sinyal tidak di-deliver — perilaku lama dipertahankan).
    }

    // Timeout: thread masih JALAN di dalam fungsi — hentikan dulu
    // (PTRACE_INTERRUPT) sebelum register dipulihkan, supaya detach
    // bersih dan thread kembali ke PC semula, bukan tertinggal di tengah
    // dlopen. Best-effort: bila interrupt gagal, tetap coba pulihkan.
    if (timed_out) {
        interrupt_and_stop();
    }

    write_mem(return_marker, &original_insn, sizeof(original_insn));

    struct iovec restore_iov{&saved_regs, sizeof(saved_regs)};
    ptrace(PTRACE_SETREGSET, tid_, reinterpret_cast<void*>(NT_PRSTATUS), &restore_iov);

    if (!hit) {
        LOGE("remote call to 0x%lx never hit the return breakpoint (timeout=%d ms)",
             func_addr, timeout_ms);
    }
    return hit;
}

}  // namespace injector
