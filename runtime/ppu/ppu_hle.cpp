/*
 * ps3recomp - PPU HLE bridge (NID -> host function dispatch)
 *
 * Connects the recompiled game's firmware imports to our HLE C libraries.
 * The game calls an imported function through its import stub; the lifter
 * emits `ps3_hle_call(<NID>, ctx)` for those addresses (see ppu_lifter.py
 * --imports). This resolves the NID to a registered HLE handler and marshals
 * the PPC calling convention into a native C call.
 *
 * PPC64 ELFv1 integer/pointer ABI: arguments in r3..r10 (gpr[3..10]), return
 * value in r3. The generic adapter casts the handler to a uint64-in/uint64-out
 * function and passes the 8 GPR argument slots; this covers the large majority
 * of cellXxx APIs (integer args/handles, s32 return). Functions that take or
 * return *pointers* need host<->guest address translation and so require a
 * per-function wrapper -- the generic path passes the raw value through.
 *
 * Compiled as C++ (matches the lifted output). Game-agnostic.
 */
#include "ppu_recomp.h"   /* ppu_context */
#include "ps3emu/nid.h"   /* ps3_nid_table, ps3_nid_entry */
#include <stdint.h>
#include <stdio.h>

/* Single flat NID -> handler table (all modules share it; resolution is by
 * NID which is globally unique). Sized for the firmware import surface. */
#define HLE_NID_CAP 4096
static ps3_nid_entry  g_hle_storage[HLE_NID_CAP];
static ps3_nid_table  g_hle_nids;
static int            g_hle_inited = 0;

extern "C" void ps3_hle_register(uint32_t nid, const char* name, void* handler)
{
    if (!g_hle_inited) { ps3_nid_table_init(&g_hle_nids, g_hle_storage, HLE_NID_CAP); g_hle_inited = 1; }
    ps3_nid_table_add(&g_hle_nids, nid, name, handler);
}

extern "C" uint32_t ps3_hle_count(void) { return g_hle_inited ? g_hle_nids.count : 0; }

/* Context-aware handlers: functions that need the full ppu_context (to read
 * args beyond the generic ABI, set registers like r13, touch memory, etc.).
 * Registered separately and dispatched before the generic table. */
typedef void (*hle_ctx_fn)(ppu_context*);
#define HLE_CTX_CAP 256
static struct { uint32_t nid; hle_ctx_fn fn; } g_ctx[HLE_CTX_CAP];
static uint32_t g_ctx_count = 0;

extern "C" void ps3_hle_register_ctx(uint32_t nid, const char* name, hle_ctx_fn fn)
{
    (void)name;
    if (g_ctx_count < HLE_CTX_CAP) { g_ctx[g_ctx_count].nid = nid; g_ctx[g_ctx_count].fn = fn; g_ctx_count++; }
}

/* Generic PPC integer/pointer ABI adapter. */
typedef uint64_t (*hle_generic)(uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t);

/* Host VM store (defined in ppu_loader.cpp) — used for the TOC save below. */
void vm_write64(uint64_t addr, uint64_t val);

/* Breadcrumb for the crash reporter: the last firmware import dispatched, so a
 * host AV inside an HLE handler names the culprit NID/function. */
extern "C" uint32_t    g_last_hle_nid  = 0;
extern "C" const char* g_last_hle_name = "";

extern "C" void ps3_hle_call(uint32_t nid, ppu_context* ctx)
{
    g_last_hle_nid = nid;
    /* PPC64 ELFv1 cross-module ABI: the caller restores its TOC right after the
     * call with `ld r2, 0x28(r1)`, expecting the import stub to have saved the
     * caller's r2 into that slot. The real .lib.stub trampoline did this; the
     * lifted --hle-stubs body (ps3_hle_call) doesn't, so without this every
     * import call leaves the caller with a garbage r2 -> all later TOC-relative
     * loads (the C++ ctor list, globals, ...) read garbage -> boot corruption. */
    vm_write64(ctx->gpr[1] + 0x28, ctx->gpr[2]);

    for (uint32_t i = 0; i < g_ctx_count; i++)
        if (g_ctx[i].nid == nid) { g_ctx[i].fn(ctx); return; }

    ps3_nid_entry* e = g_hle_inited ? ps3_nid_table_find(&g_hle_nids, nid) : nullptr;
    if (!e || !e->handler) {
        static int logged = 0;
        if (logged < 40) { fprintf(stderr, "[hle] unresolved NID 0x%08X\n", nid); logged++; }
        ctx->gpr[3] = 0;   /* CELL_OK-ish so the game keeps going */
        return;
    }
    g_last_hle_name = e->name;
    hle_generic fn = (hle_generic)e->handler;
    uint64_t r = fn(ctx->gpr[3], ctx->gpr[4], ctx->gpr[5], ctx->gpr[6],
                    ctx->gpr[7], ctx->gpr[8], ctx->gpr[9], ctx->gpr[10]);
    ctx->gpr[3] = r;   /* PPC return value */
}

/* Populated by the generated registration unit (gen_hle_nids.py). Weak so a
 * build without it still links (no HLE registered -> imports log + return 0). */
extern "C" void ppu_hle_register_all(void) __attribute__((weak));
extern "C" void ppu_hle_register_all(void) {}

extern "C" void ppu_hle_init(void) { ppu_hle_register_all(); }
