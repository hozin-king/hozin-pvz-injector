#pragma once

#include <cstdint>
#include <sys/types.h>
#include <vector>

namespace injector {

// Thin wrapper around a single ptrace-attached remote process. Everything
// here assumes arm64-v8a: register layout, calling convention (first eight
// integer args in x0-x7, return value in x0) and the breakpoint trampoline
// used to detect when a remote call has returned. Not safe to share across
// threads.
//
// v1.3: remote call berbatas waktu + bisa attach ke thread TERTENTU
// (bukan hanya main thread). Tes POCO v1.2: dlopen hang ~2 dtk di main
// thread (exit=8) sementara game tetap hidup — main thread kemungkinan
// berebut loader lock; retry di thread yang sedang tidur (futex/epoll)
// jauh lebih aman.
class RemoteProcess {
public:
    bool attach(pid_t pid);
    // Attach ke thread tertentu dari proses pid (tid != pid). Dipakai
    // retry v1.3: pilih thread yang sedang tidur.
    bool attach_tid(pid_t pid, pid_t tid);
    bool detach();

    bool read_mem(uintptr_t addr, void* buf, size_t len) const;
    bool write_mem(uintptr_t addr, const void* buf, size_t len) const;

    // Calls func_addr(args...) inside the attached process and returns the
    // value left in x0 through result. Returns false (result left
    // untouched) if the call could not be completed, e.g. the breakpoint
    // never hit within the timeout.
    bool call(uintptr_t func_addr, const std::vector<uint64_t>& args, uint64_t& result);
    // Sama, dengan timeout eksplisit (milidetik). v1.3: dlopen diberi
    // 10000 ms; syscall cepat (mmap/open/dlerror) tetap pakai default.
    bool call(uintptr_t func_addr, const std::vector<uint64_t>& args,
              uint64_t& result, int timeout_ms);

    // TID thread yang sedang di-attach (== pid untuk main thread).
    pid_t attached_tid() const { return tid_; }

private:
    // Hentikan thread yang sedang jalan (pakai PTRACE_INTERRUPT) supaya
    // register bisa dipulihkan dengan aman setelah timeout. Best-effort.
    bool interrupt_and_stop();

    pid_t pid_ = -1;
    pid_t tid_ = -1;
    int mem_fd_ = -1;
    bool attached_ = false;
};

}  // namespace injector
