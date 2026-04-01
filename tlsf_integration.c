/**
 * @file tlsf_integration.c
 * @brief TLSF allocator integration — replaces newlib malloc/free/calloc/realloc
 *        via --wrap linker flags. Also stubs _sbrk to prevent any bypass.
 *
 * Linker symbols _heap_start and _heap_end are defined in the linker script
 * and mark the boundaries of the TLSF-managed pool (all free RAM between
 * end-of-BSS and the stack region at top of RAM).
 */

#include <errno.h>
#include <reent.h>
#include <stdint.h>
#include <string.h>

#include "tlsf.h"

/* ================================================================== */
/*  Debug and feature flags for TLSF integration                       */
/*  Disable in production via -D flags to save RAM/CPU.               */
/* ================================================================== */
#ifndef TLSF_REDZONE
#define TLSF_REDZONE 1 /* 1 = enable red-zone canaries (default) */
#endif

/* Fine-grained controls (defaults chosen to preserve existing behavior)
 * - TLSF_POISON_FREE: overwrite freed memory with 0xCD and enable
 *   double-free detection (defaults to TLSF_REDZONE).
 * - TLSF_HISTORY: keep a small ring buffer of recent alloc/free ops
 *   for post-mortem debugging (defaults to TLSF_REDZONE).
 * - TLSF_PEAK_TRACK: maintain `s_current_heap_used`/`s_peak_heap_used`
 *   (small runtime cost; enabled by default).
 * - TLSF_ISR_SAFE: mask the USB IRQ around allocator ops (disabled by
 *   default; enable only if needed).
 */
#ifndef TLSF_POISON_FREE
#define TLSF_POISON_FREE TLSF_REDZONE
#endif

#ifndef TLSF_HISTORY
#define TLSF_HISTORY TLSF_REDZONE
#endif

#ifndef TLSF_PEAK_TRACK
#define TLSF_PEAK_TRACK 1
#endif

#ifndef TLSF_ISR_SAFE
#define TLSF_ISR_SAFE 0
#endif

#if TLSF_REDZONE

#define REDZONE_SIZE 8    /* bytes of canary after each alloc   */
#define REDZONE_FILL 0xFD /* canary byte pattern                */
#define FREE_FILL 0xCD    /* poison fill on free (use-after-free)*/

/*
 * Allocation tracking table — open-addressed hash table keyed by pointer.
 * Stores the user-requested size so we know exactly where the red zone is,
 * plus the return address of the caller for blame attribution.
 *
 * 4096 slots × 12 bytes = 48 KB — acceptable for a 640 KB RAM target.
 */
#define ALLOC_TABLE_BITS 12
#define ALLOC_TABLE_SIZE (1u << ALLOC_TABLE_BITS)
#define ALLOC_TABLE_MASK (ALLOC_TABLE_SIZE - 1)

typedef struct {
    void* ptr;               /* user pointer (NULL = slot empty)     */
    uint32_t requested_size; /* bytes the caller asked for           */
    void* caller;            /* __builtin_return_address(0)          */
} alloc_entry_t;

static alloc_entry_t s_alloc_table[ALLOC_TABLE_SIZE];

/* Simple hash: strip low bits (always aligned), fold with golden ratio shift */
static inline uint32_t ptr_hash(const void* p) {
    uint32_t v = (uint32_t)(uintptr_t)p >> 2;
    v *= 0x9E3779B9u; /* golden ratio */
    return v >> (32 - ALLOC_TABLE_BITS);
}

static void alloc_table_insert(void* ptr, uint32_t size, void* caller) {
    uint32_t idx = ptr_hash(ptr);
    for (uint32_t i = 0; i < ALLOC_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) & ALLOC_TABLE_MASK;
        if (s_alloc_table[slot].ptr == NULL || s_alloc_table[slot].ptr == ptr) {
            s_alloc_table[slot].ptr = ptr;
            s_alloc_table[slot].requested_size = size;
            s_alloc_table[slot].caller = caller;
            return;
        }
    }
    /* Table full — silent drop (should not happen with 4096 slots) */
}

static alloc_entry_t* alloc_table_find(void* ptr) {
    uint32_t idx = ptr_hash(ptr);
    for (uint32_t i = 0; i < ALLOC_TABLE_SIZE; i++) {
        uint32_t slot = (idx + i) & ALLOC_TABLE_MASK;
        if (s_alloc_table[slot].ptr == ptr) return &s_alloc_table[slot];
        if (s_alloc_table[slot].ptr == NULL) return NULL;
    }
    return NULL;
}

static void alloc_table_remove(void* ptr) {
    alloc_entry_t* e = alloc_table_find(ptr);
    if (!e) return;
    uint32_t slot = (uint32_t)(e - s_alloc_table);
    e->ptr = NULL;
    /* Rehash following entries to repair the open-addressing probe chain */
    for (uint32_t i = 1; i < ALLOC_TABLE_SIZE; i++) {
        uint32_t next = (slot + i) & ALLOC_TABLE_MASK;
        if (s_alloc_table[next].ptr == NULL) break;
        alloc_entry_t tmp = s_alloc_table[next];
        s_alloc_table[next].ptr = NULL;
        alloc_table_insert(tmp.ptr, tmp.requested_size, tmp.caller);
    }
}

/*
 * Global struct inspectable in debugger when a red-zone violation fires.
 */
typedef struct {
    void* user_ptr;                        /* allocation whose canary was stomped  */
    uint32_t requested_size;               /* original malloc size                 */
    void* alloc_caller;                    /* who allocated this block             */
    void* free_caller;                     /* who freed it (triggered the check)   */
    uint8_t canary_snapshot[REDZONE_SIZE]; /* actual bytes found     */
} redzone_violation_t;

volatile redzone_violation_t rz_violation;

static void redzone_handler(void) {
    volatile int hang = 1;
    while (hang) { /* set hang=0 in debugger, inspect rz_violation */
    }
}

/* ================================================================== */
/*  Double-free detection (optional)                                   */
/* ================================================================== */
#if TLSF_POISON_FREE
typedef struct {
    void* ptr;         /* pointer being double-freed           */
    void* free_caller; /* who called the second free           */
} double_free_info_t;

volatile double_free_info_t df_info;

static void double_free_handler(void) {
    volatile int hang = 1;
    while (hang) { /* set hang=0 in debugger, inspect df_info */
    }
}
#endif

/* ================================================================== */
/*  Allocation history ring buffer (last 256 operations)               */
/*  Can be disabled to save RAM/CPU by setting TLSF_HISTORY=0.        */
/* ================================================================== */
#if TLSF_HISTORY
#define HISTORY_BITS 8
#define HISTORY_SIZE (1u << HISTORY_BITS)
#define HISTORY_MASK (HISTORY_SIZE - 1)

typedef struct {
    void* ptr;
    uint32_t size;
    void* caller;
    uint8_t op; /* 'M'=malloc, 'F'=free, 'R'=realloc   */
} history_entry_t;

volatile history_entry_t s_history[HISTORY_SIZE];
volatile uint32_t s_history_idx = 0;

static void history_record(uint8_t op, void* ptr, uint32_t size, void* caller) {
    uint32_t idx = __atomic_fetch_add(&s_history_idx, 1, __ATOMIC_RELAXED) & HISTORY_MASK;
    s_history[idx].op = op;
    s_history[idx].ptr = ptr;
    s_history[idx].size = size;
    s_history[idx].caller = caller;
}
#else
static inline void history_record(uint8_t op, void* ptr, uint32_t size, void* caller) {
    (void)op;
    (void)ptr;
    (void)size;
    (void)caller;
}
#endif

static void write_canary(void* ptr, uint32_t user_size) {
    memset((uint8_t*)ptr + user_size, REDZONE_FILL, REDZONE_SIZE);
}

/*
 * Returns 1 if canary intact, 0 if violated.
 * On violation, fills rz_violation and calls handler.
 */
static int check_canary(void* ptr, const alloc_entry_t* entry, void* free_caller) {
    const uint8_t* canary = (const uint8_t*)ptr + entry->requested_size;
    for (int i = 0; i < REDZONE_SIZE; i++) {
        if (canary[i] != REDZONE_FILL) {
            /* Violation! Capture details for debugger. */
            rz_violation.user_ptr = ptr;
            rz_violation.requested_size = entry->requested_size;
            rz_violation.alloc_caller = entry->caller;
            rz_violation.free_caller = free_caller;
            memcpy((void*)rz_violation.canary_snapshot, canary, REDZONE_SIZE);
            redzone_handler();
            return 0;
        }
    }
    return 1;
}

#endif /* TLSF_REDZONE */

/* ================================================================== */
/*  ISR-safe critical section for TLSF                                 */
/*  Masks only the USB interrupt during allocator operations so that   */
/*  the USB RX callback cannot re-enter TLSF while main-loop code is  */
/*  inside malloc/free/realloc.  Other interrupts remain enabled.      */
/* ================================================================== */
#include "uniHal.h" /* HAL + NVIC + IRQn definitions */

#ifdef __STM32H7xx_HAL
#define USB_IRQn OTG_FS_IRQn
#else
#define USB_IRQn USB_DRD_FS_IRQn
#endif

static inline void alloc_enter(uint8_t op, void* caller) {
    (void)op;
    (void)caller;
#if TLSF_ISR_SAFE
    HAL_NVIC_DisableIRQ(USB_IRQn);
#endif
}

static inline void alloc_exit(void) {
#if TLSF_ISR_SAFE
    HAL_NVIC_EnableIRQ(USB_IRQn);
#endif
}

/* Linker-provided symbols */
extern uint8_t _heap_start;
extern uint8_t _heap_end;

/* Single TLSF instance for the entire system */
static tlsf_t s_tlsf = NULL;
static volatile int s_tlsf_initializing = 0;

/* Peak heap-usage tracking (updated in malloc/free/realloc wrappers) */
#if TLSF_PEAK_TRACK
static size_t s_current_heap_used = 0;
static size_t s_peak_heap_used = 0;
#endif

/**
 * @brief Ensure the TLSF pool is initialized. Safe to call multiple times.
 *        Called lazily on first allocation (handles C++ static constructors
 *        that allocate before main()).
 */
static void tlsf_ensure_init(void) {
    if (s_tlsf) return;

    /* Guard against re-entrancy (e.g. printf->malloc during init) */
    if (s_tlsf_initializing) return;
    s_tlsf_initializing = 1;

    size_t pool_size = (size_t)(&_heap_end - &_heap_start);
    s_tlsf = tlsf_create_with_pool(&_heap_start, pool_size);

    s_tlsf_initializing = 0;
}

/* ------------------------------------------------------------------ */
/*  Public API: callable from application code if needed              */
/* ------------------------------------------------------------------ */

/**
 * @brief Return the TLSF instance (initializes if necessary).
 */
tlsf_t tlsf_get_instance(void) {
    tlsf_ensure_init();
    return s_tlsf;
}

/**
 * @brief Return total pool size in bytes.
 */
size_t tlsf_heap_size(void) { return (size_t)(&_heap_end - &_heap_start); }

/* Walk callback — accumulates used and free byte counts. */
typedef struct {
    size_t used;
    size_t free;
} tlsf_walk_accum_t;

static void walk_accum(void* ptr, size_t size, int used, void* user) {
    (void)ptr;
    tlsf_walk_accum_t* acc = (tlsf_walk_accum_t*)user;
    if (used)
        acc->used += size;
    else
        acc->free += size;
}

/**
 * @brief Populate a status snapshot of the TLSF heap.
 */
void tlsf_get_status(size_t* total, size_t* used, size_t* free_bytes, int* integrity_ok) {
    tlsf_ensure_init();

    *total = tlsf_heap_size();

    tlsf_walk_accum_t acc = {0, 0};
    tlsf_walk_pool(tlsf_get_pool(s_tlsf), walk_accum, &acc);
    *used = acc.used;
    *free_bytes = acc.free;
    *integrity_ok = (tlsf_check(s_tlsf) == 0) ? 1 : 0;
}

/**
 * @brief Return peak heap usage observed since boot.
 */
#if TLSF_PEAK_TRACK
void tlsf_get_peak(size_t* peak_heap_used) { *peak_heap_used = s_peak_heap_used; }
#else
void tlsf_get_peak(size_t* peak_heap_used) {
    (void)peak_heap_used;
    *peak_heap_used = 0;
}
#endif

/* ------------------------------------------------------------------ */
/*  --wrap interceptors for standard C allocation functions            */
/* ------------------------------------------------------------------ */

void* __wrap_malloc(size_t size) {
    tlsf_ensure_init();
    alloc_enter('M', __builtin_return_address(0));
#if TLSF_REDZONE
    void* caller = __builtin_return_address(0);
    /* Over-allocate to make room for canary sentinel after user data */
    void* ptr = tlsf_malloc(s_tlsf, size + REDZONE_SIZE);
    if (ptr) {
#if TLSF_PEAK_TRACK
        s_current_heap_used += tlsf_block_size(ptr);
        if (s_current_heap_used > s_peak_heap_used) s_peak_heap_used = s_current_heap_used;
#endif
        write_canary(ptr, (uint32_t)size);
        alloc_table_insert(ptr, (uint32_t)size, caller);
#if TLSF_HISTORY
        history_record('M', ptr, (uint32_t)size, caller);
#endif
    }
    alloc_exit();
    return ptr;
#else
    void* ptr = tlsf_malloc(s_tlsf, size);
    if (ptr) {
#if TLSF_PEAK_TRACK
        s_current_heap_used += tlsf_block_size(ptr);
        if (s_current_heap_used > s_peak_heap_used) s_peak_heap_used = s_current_heap_used;
#endif
    }
    alloc_exit();
    return ptr;
#endif
}

void __wrap_free(void* ptr) {
    if (!ptr) return;
    tlsf_ensure_init();
    alloc_enter('F', __builtin_return_address(0));
#if TLSF_REDZONE
    void* caller = __builtin_return_address(0);
    alloc_entry_t* entry = alloc_table_find(ptr);
    if (entry) {
        check_canary(ptr, entry, caller);
#if TLSF_POISON_FREE
        /* Poison user data to detect use-after-free */
        memset(ptr, FREE_FILL, entry->requested_size + REDZONE_SIZE);
#endif
        alloc_table_remove(ptr);
    } else {
#if TLSF_POISON_FREE
        /* Not in table — check for double-free (already poisoned with 0xCD) */
        if (*(volatile uint32_t*)ptr == 0xCDCDCDCDu) {
            df_info.ptr = ptr;
            df_info.free_caller = caller;
            double_free_handler(); /* spins — inspect df_info in debugger */
        }
#endif
    }
#if TLSF_HISTORY
    history_record('F', ptr, 0, caller);
#endif
#endif
#if TLSF_PEAK_TRACK
    s_current_heap_used -= tlsf_block_size(ptr);
#endif
    tlsf_free(s_tlsf, ptr);
    alloc_exit();
}

void* __wrap_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    /* Overflow check */
    if (nmemb && (total / nmemb != size)) return NULL;

    void* ptr = __wrap_malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void* __wrap_realloc(void* ptr, size_t size) {
    tlsf_ensure_init();
    alloc_enter('R', __builtin_return_address(0));
#if TLSF_REDZONE
    void* caller = __builtin_return_address(0);
    /* Check old block's canary before realloc touches it */
    if (ptr) {
        alloc_entry_t* old_entry = alloc_table_find(ptr);
        if (old_entry) {
            check_canary(ptr, old_entry, caller);
            alloc_table_remove(ptr);
        }
    }
    size_t old_size = ptr ? tlsf_block_size(ptr) : 0;
    void* new_ptr = tlsf_realloc(s_tlsf, ptr, size + REDZONE_SIZE);
    if (new_ptr) {
        size_t new_size = tlsf_block_size(new_ptr);
#if TLSF_PEAK_TRACK
        s_current_heap_used = s_current_heap_used - old_size + new_size;
        if (s_current_heap_used > s_peak_heap_used) s_peak_heap_used = s_current_heap_used;
#endif
        write_canary(new_ptr, (uint32_t)size);
        alloc_table_insert(new_ptr, (uint32_t)size, caller);
#if TLSF_HISTORY
        history_record('R', new_ptr, (uint32_t)size, caller);
#endif
    } else if (size == 0 && ptr) {
#if TLSF_PEAK_TRACK
        s_current_heap_used -= old_size;
#endif
    }
    alloc_exit();
    return new_ptr;
#else
    size_t old_size = ptr ? tlsf_block_size(ptr) : 0;
    void* new_ptr = tlsf_realloc(s_tlsf, ptr, size);
    if (new_ptr) {
        size_t new_size = tlsf_block_size(new_ptr);
#if TLSF_PEAK_TRACK
        s_current_heap_used = s_current_heap_used - old_size + new_size;
        if (s_current_heap_used > s_peak_heap_used) s_peak_heap_used = s_current_heap_used;
#endif
    } else if (size == 0 && ptr) {
        /* realloc(ptr, 0) acts as free in some implementations */
#if TLSF_PEAK_TRACK
        s_current_heap_used -= old_size;
#endif
    }
    alloc_exit();
    return new_ptr;
#endif
}

/* ------------------------------------------------------------------ */
/*  Newlib reentrant variants (_malloc_r etc.)                         */
/*  These just delegate to the non-reentrant wrappers above.          */
/* ------------------------------------------------------------------ */

void* __wrap__malloc_r(struct _reent* r, size_t size) {
    (void)r;
    return __wrap_malloc(size);
}

void __wrap__free_r(struct _reent* r, void* ptr) {
    (void)r;
    __wrap_free(ptr);
}

void* __wrap__calloc_r(struct _reent* r, size_t nmemb, size_t size) {
    (void)r;
    return __wrap_calloc(nmemb, size);
}

void* __wrap__realloc_r(struct _reent* r, void* ptr, size_t size) {
    (void)r;
    return __wrap_realloc(ptr, size);
}

/* ------------------------------------------------------------------ */
/*  _sbrk stub — prevent any code from bypassing TLSF                 */
/* ------------------------------------------------------------------ */

void* _sbrk(ptrdiff_t incr) {
    (void)incr;
    errno = ENOMEM;
    return (void*)-1;
}
