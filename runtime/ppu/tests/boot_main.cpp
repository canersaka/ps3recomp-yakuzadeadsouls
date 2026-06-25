/*
 * ps3recomp - integrated PPU boot harness (first-boot attempt).
 *
 * Links the whole PPU runtime half into one executable and starts executing
 * the recompiled game's entry point:
 *
 *   lifted code (ppu_recomp.c) + loader (ppu_loader.cpp) + HLE bridge
 *   (ppu_hle.cpp + generated NID table) + HLE libs (cellGcmSys, rsx_commands)
 *
 * It loads the real EBOOT image, registers the lifted functions and the HLE
 * NID handlers, then dispatches the entry. Execution runs real Uncharted boot
 * code until it reaches a function outside the lifted subset (logged by the
 * unlifted stub), an unimplemented firmware import (logged by ps3_hle_call),
 * or an lv2 syscall (logged by lv2_syscall) -- telling us exactly what to
 * implement next.
 *
 * This proves the integration builds + runs; a full-image build additionally
 * needs the lifter to split output into multiple TUs (88 MB single-file
 * otherwise).
 */
#include "ppu_recomp.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" {
uint32_t ppu_load_elf(const char* path);
void     ppu_recomp_register(void);
void     ppu_hle_init(void);
void     ppu_sysprx_register(void);
void     ppu_fs_register(void);
int      ppu_run(uint32_t entry_opd, uint32_t stack_top);
extern const char* ppu_vfs_root;   /* host dir that PS3 mount points map into */
}

#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
/* Last-chance crash reporter: vm_base accesses are bounds-guarded, so a real
 * access violation means a HOST pointer deref (e.g. a bad function pointer or a
 * runtime-struct walk). Print the faulting address and the RIP as a module
 * offset (RVA) so it can be symbolized with llvm-symbolizer against the PDB. */
static LONG WINAPI ydkj_crash_filter(EXCEPTION_POINTERS* ep)
{
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    fprintf(stderr, "\n[CRASH] code=0x%08lX rip=%p\n",
            (unsigned long)er->ExceptionCode, er->ExceptionAddress);
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
        fprintf(stderr, "[CRASH] %s fault address 0x%llX\n",
                er->ExceptionInformation[0] ? "write" : "read",
                (unsigned long long)er->ExceptionInformation[1]);
    HMODULE mod = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)er->ExceptionAddress, &mod);
    fprintf(stderr, "[CRASH] module=%p rva=0x%llX  (llvm-symbolizer --obj=ydkj_boot.exe 0x%llX)\n",
            (void*)mod, (unsigned long long)((char*)er->ExceptionAddress - (char*)mod),
            (unsigned long long)((char*)er->ExceptionAddress - (char*)mod));
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

/* Derive the VFS root (the dir containing PS3_GAME) from the EBOOT path
 * <root>/PS3_GAME/USRDIR/EBOOT.elf  -> <root>. $PS3_VFS_ROOT overrides. */
static char s_vfs_root[1024];
static void derive_vfs_root(const char* eboot)
{
    const char* env = getenv("PS3_VFS_ROOT");
    if (env && *env) { ppu_vfs_root = env; return; }
    strncpy(s_vfs_root, eboot, sizeof s_vfs_root - 1);
    for (char* p = s_vfs_root; *p; p++) if (*p == '\\') *p = '/';
    /* strip three trailing components: EBOOT.elf / USRDIR / PS3_GAME */
    for (int i = 0; i < 3; i++) { char* s = strrchr(s_vfs_root, '/'); if (s) *s = 0; }
    if (!s_vfs_root[0]) strcpy(s_vfs_root, ".");
    ppu_vfs_root = s_vfs_root;
}

/* Host-provided symbols the runtime + HLE libs need. */
extern "C" uint8_t* vm_base = nullptr;
extern "C" uint32_t ppu_vm_size;   /* defined in ppu_loader.cpp (OOB guard) */
extern "C" void lv2_init_syscalls(void);   /* runtime/syscalls/lv2_register.c */
/* g_ps3_guest_caller is defined (default NULL) by libs/system/cellSysutil.c in
 * the runtime library; the boot harness installs no guest callbacks, so we just
 * leave it at its default rather than re-defining it (would be a duplicate
 * symbol at link). */

/* The flat VM treats every address as valid RAM, so it must span every region
 * the PS3 memory map uses. The game's heap maps at 0x20000000+ and reaches
 * ~0x50000000, but sys_ppu_thread_create allocates thread stacks in the PS3
 * stack region at 0xD0000000-0xDFFFFFFF (vm.h: VM_STACK_BASE). Without covering
 * that, every spawned thread's stack access is OOB (reads 0 / writes dropped)
 * and the thread crashes. Size to include the stack region: ~3.75 GB, lazily
 * committed by the OS (only touched pages are backed). */
#define VM_SIZE    0xE0000000u
#define STACK_TOP  0x0FF00000u   /* main-thread stack, below the 0x10000000 segment */

int main(int argc, char** argv)
{
    if (argc < 2) { printf("usage: %s <EBOOT.elf>\n", argv[0]); return 2; }

#ifdef _WIN32
    SetUnhandledExceptionFilter(ydkj_crash_filter);
#endif

    /* Native VA mapping: reserve the guest address space at its OWN host
     * addresses, so guest address == host address and vm_base = 0. This removes
     * ALL guest<->host pointer translation -- lifted code (vm_base + a) and HLE
     * C code (raw *guest_ptr) reach the same bytes -- killing the whole class of
     * "HLE deref'd a guest pointer as a host pointer" crashes. Guest memory
     * stays big-endian, so vm_read/write still byte-swap; HLE functions that
     * write multi-byte values through a raw pointer are now address-correct but
     * host-endian (fix per-function with vm_write* as they matter). */
#ifdef _WIN32
    /* Reserve the specific regions the PS3 memory map uses, at their own host
     * VAs (one giant low reservation conflicts with the process's existing low
     * allocations). Commit lazily on first access via a vectored handler. */
    struct { uintptr_t base; size_t size; const char* what; } regions[] = {
        { 0x00010000, 0x1FFF0000, "image+TLS+main stack+mmapper (0x10000..0x20000000)" },
        { 0x20000000, 0x40000000, "RSX-map + user heap (0x20000000..0x60000000)" },
        { 0xD0000000, 0x10000000, "thread stacks (0xD0000000..0xE0000000)" },
    };
    for (size_t i = 0; i < sizeof(regions)/sizeof(regions[0]); i++) {
        void* got = VirtualAlloc((void*)regions[i].base, regions[i].size,
                                 MEM_RESERVE, PAGE_READWRITE);
        if (got != (void*)regions[i].base) {
            fprintf(stderr, "[boot] native VA reserve failed for %s: got %p (err %lu)\n",
                    regions[i].what, got, (unsigned long)GetLastError());
            return 1;
        }
        fprintf(stderr, "[boot] reserved %s\n", regions[i].what);
    }
    /* Commit-on-fault: turn an access to a reserved-but-uncommitted guest page
     * into a committed zero page, so we don't pay 2+ GB of commit up front. */
    AddVectoredExceptionHandler(1, [](EXCEPTION_POINTERS* ep) -> LONG {
        EXCEPTION_RECORD* er = ep->ExceptionRecord;
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
            void* addr = (void*)er->ExceptionInformation[1];
            if (VirtualAlloc(addr, 1, MEM_COMMIT, PAGE_READWRITE))
                return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
    vm_base = (uint8_t*)0;   /* guest addr == host addr */
#else
    vm_base = (uint8_t*)calloc(1, VM_SIZE);
    if (!vm_base) { printf("vm alloc failed\n"); return 1; }
#endif
    ppu_vm_size = VM_SIZE;   /* enable OOB guard */

    uint32_t entry = ppu_load_elf(argv[1]);
    if (!entry) { printf("load failed\n"); return 1; }

    derive_vfs_root(argv[1]);
    printf("[boot] VFS root: %s\n", ppu_vfs_root);

    ppu_recomp_register();   /* lifted function table -> address map */
    ppu_hle_init();          /* firmware import NID -> HLE handlers */
    ppu_sysprx_register();   /* boot-critical CRT (sys_initialize_tls, ...) */
    ppu_fs_register();       /* cellFs VFS over the real game directory */
    lv2_init_syscalls();     /* real lv2 syscall table (semaphore/memory/fs/...) */

    printf("\n[boot] dispatching entry OPD 0x%08X (stack top 0x%08X)\n\n", entry, STACK_TOP);
    int rc = ppu_run(entry, STACK_TOP);
    printf("\n[boot] ppu_run returned %d (entry function unwound)\n", rc);
    return 0;
}
