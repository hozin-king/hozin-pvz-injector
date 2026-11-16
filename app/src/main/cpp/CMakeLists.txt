cmake_minimum_required(VERSION 3.22.1)
project(HozinPvZInjector CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# --- Dobby (hook library) diambil saat build via FetchContent ---
# Pakai URL arsip (bukan git clone) agar tidak gagal di runner CI.
# Patch di bawah = 5 patch yang sama dengan bussid-injector (terbukti
# menghijaukan CI di hozin-ue-hook / BUSSID / TR): upstream jmpews/Dobby
# 5dfc854 "broken" untuk NDK modern. JANGAN pakai Dobby mentah.
FetchContent_Declare(
    dobby
    URL https://github.com/jmpews/Dobby/archive/5dfc8546954ce3b3198132ab13fddb89ee92cdd7.zip
)
FetchContent_GetProperties(dobby)
if(NOT dobby_POPULATED)
    FetchContent_Populate(dobby)

    # 1. closure_bridge_arm64.asm: sintaks Mach-O "@PAGE"/"@PAGEOFF"
    #    ditolak assembler LLVM pada target ELF.
    set(_f "${dobby_SOURCE_DIR}/source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.asm")
    file(READ "${_f}" _c)
    string(REPLACE
        "adrp TMP_REG_0, cdecl(common_closure_bridge_handler)@PAGE\nadd TMP_REG_0, TMP_REG_0, cdecl(common_closure_bridge_handler)@PAGEOFF\nblr TMP_REG_0"
        "ldr TMP_REG_0, common_closure_bridge_handler_addr\nblr TMP_REG_0"
        _c "${_c}")
    file(WRITE "${_f}" "${_c}")

    # 2. common/os_arch_features.h: putus circular include.
    set(_f "${dobby_SOURCE_DIR}/common/os_arch_features.h")
    file(READ "${_f}" _c)
    string(REPLACE
        "#include <sys/types.h>\n#include <stddef.h>\n#include \"pac_kit.h\"\n\n#include \"PlatformUnifiedInterface/platform.h\""
        "#include <sys/types.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <unistd.h>\n#include <sys/mman.h>\n#include \"pac_kit.h\""
        _c "${_c}")
    string(REPLACE
        "  auto page = (void *)ALIGN_FLOOR(address, OSMemory::PageSize());\n  if (!OSMemory::SetPermission(page, OSMemory::PageSize(), kReadExecute)) {\n    return;\n  }"
        "  (void)size;\n  long page_size = sysconf(_SC_PAGESIZE);\n  if (page_size <= 0)\n    return;\n  void *page = (void *)((uintptr_t)address & ~((uintptr_t)page_size - 1));\n  mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);"
        _c "${_c}")
    file(WRITE "${_f}" "${_c}")

    # 3. code-patch-tool-posix.cc: include "core/arch/Cpu.h" tertinggal.
    set(_f "${dobby_SOURCE_DIR}/source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc")
    file(READ "${_f}" _c)
    string(REPLACE
        "#include \"core/arch/Cpu.h\""
        "// (patched: pvz-injector) upstream menghapus core/arch/Cpu.h tapi include tertinggal"
        _c "${_c}")
    file(WRITE "${_f}" "${_c}")

    # 4. ProcessRuntime.cc: a.start adalah method; "load_address" -> "base".
    set(_f "${dobby_SOURCE_DIR}/source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntime.cc")
    file(READ "${_f}" _c)
    string(REPLACE "return (a.start < b.start);" "return (a.start() < b.start());" _c "${_c}")
    string(REPLACE "module.load_address" "module.base" _c "${_c}")
    file(WRITE "${_f}" "${_c}")

    # 5. SymbolResolver plugin: "load_address" -> "base".
    set(_f "${dobby_SOURCE_DIR}/builtin-plugin/SymbolResolver/elf/dobby_symbol_resolver.cc")
    file(READ "${_f}" _c)
    string(REPLACE "load_address" "base" _c "${_c}")
    file(WRITE "${_f}" "${_c}")

    message(STATUS "[pvz-injector] Patch Dobby selesai")

    add_subdirectory(${dobby_SOURCE_DIR} ${dobby_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# --- Dear ImGui (MIT) — vendored, matched set 1.88 WIP ---
# Core + backend OpenGL3 (ES2) + backend Android (input). Dipakai menu
# native di dalam proses game (hook eglSwapBuffers).
add_library(imgui STATIC
    thirdparty/imgui/imgui.cpp
    thirdparty/imgui/imgui_draw.cpp
    thirdparty/imgui/imgui_widgets.cpp
    thirdparty/imgui/imgui_tables.cpp
    thirdparty/imgui/backends/imgui_impl_opengl3.cpp
    thirdparty/imgui/backends/imgui_impl_android.cpp
)
target_include_directories(imgui PUBLIC
    thirdparty/imgui
    thirdparty/imgui/backends
)
target_link_libraries(imgui log android EGL GLESv2)

# --- payload: library yang di-dlopen ke proses game ---
add_library(payload SHARED
    payload/payload_main.cpp
)
target_include_directories(payload PRIVATE
    ${dobby_SOURCE_DIR}/include
    thirdparty/imgui
    thirdparty/imgui/backends
)
target_link_libraries(payload imgui dobby_static log dl EGL GLESv2 android)
# Static-link STL: payload tidak bergantung pada libc++_shared game.
target_link_options(payload PRIVATE -static-libstdc++)
set_target_properties(payload PROPERTIES OUTPUT_NAME "payload")

# --- injector: standalone PIE binary, run as root via `su -c`. Tidak
# pernah di-dlopen, hanya dieksekusi langsung; output di-rename jadi .so
# supaya AGP membundelnya di lib/<ABI>/ seperti library biasa. Setelah
# build, verifikasi lib/arm64-v8a/libinjector.so ada di APK dan ukurannya
# seperti binary beneran, bukan 0 byte.
add_executable(libinjector
    injector/injector_main.cpp
    injector/proc_maps.cpp
    injector/remote_call_arm64.cpp
)
target_link_libraries(libinjector log dl)
set_target_properties(libinjector PROPERTIES SUFFIX ".so")
