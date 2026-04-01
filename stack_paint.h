#ifndef STACK_PAINT_H
#define STACK_PAINT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fill the unused stack region with a sentinel pattern (0xDEADBEEF).
 *        Call as early as possible in main(), before any large stack usage.
 */
void stack_paint_init(void);

/**
 * @brief Scan the painted stack region and report high-water-mark statistics.
 * @param stack_total   Total stack region size in bytes.
 * @param stack_peak    Peak stack usage (high water mark) in bytes.
 * @param stack_free    Minimum free stack observed in bytes.
 */
void stack_get_hwm(size_t* stack_total, size_t* stack_peak, size_t* stack_free);

#ifdef __cplusplus
}
#endif

#endif /* STACK_PAINT_H */
