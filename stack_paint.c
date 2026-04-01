#include "stack_paint.h"

#include <stdint.h>

#define STACK_SENTINEL 0xDEADBEEFU

/* Linker-provided symbols */
extern uint8_t _heap_end; /* bottom of stack region (top of TLSF heap) */
extern uint8_t _estack;   /* top of stack (initial SP, top of RAM)     */

void stack_paint_init(void) {
    /* Get current stack pointer — everything below it is unused stack space */
    volatile uint32_t* sp;
    __asm volatile("mov %0, sp" : "=r"(sp));

    /* Paint from bottom of stack region up to (SP - 64 words / 256 bytes).
       The safety margin avoids clobbering our own frame and caller chain. */
    volatile uint32_t* bottom = (volatile uint32_t*)(uintptr_t)&_heap_end;
    volatile uint32_t* top = sp - 64;

    for (volatile uint32_t* p = bottom; p < top; p++) {
        *p = STACK_SENTINEL;
    }
}

/**
 * @brief Get stack high-water mark (HWM) information.
 *
 * @param stack_total Pointer to store total stack size in bytes.
 * @param stack_peak Pointer to store peak stack usage in bytes.
 * @param stack_free Pointer to store free stack space in bytes.
 */
void stack_get_hwm(size_t* stack_total, size_t* stack_peak, size_t* stack_free) {
    const uint32_t* bottom = (const uint32_t*)(uintptr_t)&_heap_end;
    const uint32_t* top = (const uint32_t*)(uintptr_t)&_estack;

    *stack_total = (size_t)((uintptr_t)&_estack - (uintptr_t)&_heap_end);

    /* Count consecutive sentinel words from the bottom (lowest address) upward.
       The first non-sentinel word marks the deepest stack penetration. */
    size_t untouched_words = 0;
    for (const uint32_t* p = bottom; p < top; p++) {
        if (*p != STACK_SENTINEL) break;
        untouched_words++;
    }

    size_t untouched_bytes = untouched_words * sizeof(uint32_t);
    *stack_free = untouched_bytes;
    *stack_peak = *stack_total - untouched_bytes;
}
