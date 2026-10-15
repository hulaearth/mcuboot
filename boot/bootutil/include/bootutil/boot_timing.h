/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BOOTUTIL_BOOT_TIMING_H
#define BOOTUTIL_BOOT_TIMING_H

#if defined(CONFIG_N6_BOOT_TIMING)
#include <stdint.h>
#include <zephyr/kernel.h>

#ifdef __cplusplus
extern "C" {
#endif

void n6_boot_timing_record(const char *phase, int area, uint32_t bytes,
                           int64_t start_ms, int result);
void n6_boot_timing_dump(void);

#ifdef __cplusplus
}
#endif

#define N6_BOOT_TIME_BEGIN(name) int64_t name = k_uptime_get()
#define N6_BOOT_TIME_END(phase, area, bytes, start, result) \
    n6_boot_timing_record((phase), (area), (bytes), (start), (result))
#define N6_BOOT_TIME_DUMP() n6_boot_timing_dump()
#else
#define N6_BOOT_TIME_BEGIN(name) do { } while (0)
#define N6_BOOT_TIME_END(phase, area, bytes, start, result) do { } while (0)
#define N6_BOOT_TIME_DUMP() do { } while (0)
#endif

#endif /* BOOTUTIL_BOOT_TIMING_H */
