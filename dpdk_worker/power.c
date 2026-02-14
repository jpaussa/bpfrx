/* SPDX-License-Identifier: GPL-2.0-or-later
 * power.c — CPU frequency scaling via DPDK rte_power.
 *
 * Integrates with Linux cpufreq governors (intel_pstate, acpi-cpufreq)
 * to scale per-core frequency. Used by interrupt and adaptive RX modes
 * to reduce power consumption when idle.
 *
 * In interrupt mode at idle:
 *   - CPU enters C6 sleep state (~0W per core)
 *   - Frequency drops to minimum P-state
 *   - Wake-up latency: 10-100us depending on C-state depth
 */

#include <stdio.h>
#include <rte_power.h>
#include <rte_lcore.h>

/**
 * power_init — Initialize per-lcore power management.
 *
 * Enables CPU frequency scaling for the given lcore. Must be called
 * before power_scale_up/down.
 *
 * @lcore_id: The lcore to enable power management for
 */
void
power_init(unsigned lcore_id)
{
	int ret = rte_power_init(lcore_id);
	if (ret < 0) {
		/* Not fatal — power scaling just won't work.
		 * Common on VMs without cpufreq driver. */
		printf("lcore %u: power management init failed (rc=%d), "
		       "frequency scaling disabled\n", lcore_id, ret);
	} else {
		printf("lcore %u: power management initialized\n", lcore_id);
	}
}

/**
 * power_scale_down — Drop CPU to lowest P-state.
 *
 * Called when switching to interrupt mode (about to sleep).
 * Reduces frequency to save power during idle periods.
 *
 * @lcore_id: The lcore to scale down
 */
void
power_scale_down(unsigned lcore_id)
{
	rte_power_freq_min(lcore_id);
}

/**
 * power_scale_up — Boost CPU to maximum P-state.
 *
 * Called when switching back to poll mode (traffic arriving).
 * Maximizes frequency for lowest-latency packet processing.
 *
 * @lcore_id: The lcore to scale up
 */
void
power_scale_up(unsigned lcore_id)
{
	rte_power_freq_max(lcore_id);
}
