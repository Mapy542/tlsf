/**
 * @file tlsf_newdelete.cpp
 * @brief Override C++ operator new/delete to route through malloc/free,
 *        which are intercepted by the TLSF --wrap hooks.
 */

#include <cstdlib>
#include <new>

void* operator new(std::size_t size) {
    void* p = malloc(size);
    if (!p)
        while (1) {
        } /* Out of memory — trap (no exceptions on embedded) */
    return p;
}

void* operator new[](std::size_t size) {
    void* p = malloc(size);
    if (!p)
        while (1) {
        }
    return p;
}

void* operator new(std::size_t size, const std::nothrow_t&) noexcept { return malloc(size); }

void* operator new[](std::size_t size, const std::nothrow_t&) noexcept { return malloc(size); }

void operator delete(void* ptr) noexcept { free(ptr); }

void operator delete[](void* ptr) noexcept { free(ptr); }

void operator delete(void* ptr, std::size_t) noexcept { free(ptr); }

void operator delete[](void* ptr, std::size_t) noexcept { free(ptr); }
