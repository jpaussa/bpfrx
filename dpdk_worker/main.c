/* SPDX-License-Identifier: GPL-2.0-or-later
 * main.c — DPDK worker entry point.
 *
 * Initializes EAL, configures ports, allocates shared memory,
 * launches per-lcore packet processing loops, handles signals.
 */

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/* Forward declarations for RX loop functions */
extern void rx_loop_poll(struct lcore_conf *conf);
extern void rx_loop_interrupt(struct lcore_conf *conf);
extern void rx_loop_adaptive(struct lcore_conf *conf);

/* RX loop dispatch table */
typedef void (*rx_loop_fn)(struct lcore_conf *conf);

static rx_loop_fn rx_loops[] = {
	[RX_MODE_POLL]      = rx_loop_poll,
	[RX_MODE_INTERRUPT] = rx_loop_interrupt,
	[RX_MODE_ADAPTIVE]  = rx_loop_adaptive,
};

/* Global state */
static struct shared_memory *g_shm;
static struct rte_mempool *g_pktmbuf_pool;
static struct lcore_conf g_lcore_conf[MAX_LCORES];
struct lcore_counters *lcore_counter_array[MAX_LCORES];

static volatile int g_force_quit;

/* ============================================================
 * Signal handling
 * ============================================================ */

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\nSignal %d received, preparing to exit...\n", signum);
		g_force_quit = 1;
		if (g_shm)
			g_shm->shutdown = 1;
	}
}

/* ============================================================
 * Port configuration
 * ============================================================ */

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
		},
	},
};

static int
port_init(uint16_t port_id, struct rte_mempool *mbuf_pool,
          uint16_t nb_rx_queues, uint16_t nb_tx_queues)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_eth_dev_info dev_info;
	int ret;

	if (!rte_eth_dev_is_valid_port(port_id))
		return -1;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		fprintf(stderr, "Error getting dev info for port %u: %s\n",
		        port_id, rte_strerror(-ret));
		return ret;
	}

	/* Adjust RSS hash function to what the device supports */
	port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

	ret = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues,
	                            &port_conf);
	if (ret != 0) {
		fprintf(stderr, "Error configuring port %u: %s\n",
		        port_id, rte_strerror(-ret));
		return ret;
	}

	/* Setup RX queues */
	for (uint16_t q = 0; q < nb_rx_queues; q++) {
		ret = rte_eth_rx_queue_setup(port_id, q, 1024,
		                             rte_eth_dev_socket_id(port_id),
		                             NULL, mbuf_pool);
		if (ret < 0) {
			fprintf(stderr, "Error setting up RX queue %u on port %u: %s\n",
			        q, port_id, rte_strerror(-ret));
			return ret;
		}
	}

	/* Setup TX queues */
	for (uint16_t q = 0; q < nb_tx_queues; q++) {
		ret = rte_eth_tx_queue_setup(port_id, q, 1024,
		                             rte_eth_dev_socket_id(port_id),
		                             NULL);
		if (ret < 0) {
			fprintf(stderr, "Error setting up TX queue %u on port %u: %s\n",
			        q, port_id, rte_strerror(-ret));
			return ret;
		}
	}

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		fprintf(stderr, "Error starting port %u: %s\n",
		        port_id, rte_strerror(-ret));
		return ret;
	}

	/* Enable promiscuous mode */
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0) {
		fprintf(stderr, "Error enabling promiscuous on port %u: %s\n",
		        port_id, rte_strerror(-ret));
		return ret;
	}

	return 0;
}

/* ============================================================
 * Shared memory allocation
 * ============================================================ */

static struct shared_memory *
shm_alloc(void)
{
	struct shared_memory *shm;

	shm = rte_zmalloc("shared_memory", sizeof(*shm), RTE_CACHE_LINE_SIZE);
	if (!shm) {
		fprintf(stderr, "Failed to allocate shared memory structure\n");
		return NULL;
	}

	shm->magic = SHM_MAGIC;
	shm->version = SHM_VERSION;
	shm->config_generation = 0;
	shm->rx_mode = RX_MODE_POLL;
	shm->shutdown = 0;

	if (tables_init(shm) < 0) {
		rte_free(shm);
		return NULL;
	}

	return shm;
}

/* ============================================================
 * Table initialization
 * ============================================================ */

int
tables_init(struct shared_memory *shm)
{
	/* TODO: Create rte_hash tables for sessions, zones, policies, etc.
	 *
	 * Example for sessions:
	 *   struct rte_hash_parameters params = {
	 *       .name = "sessions_v4",
	 *       .entries = MAX_SESSIONS,
	 *       .key_len = sizeof(struct session_key),
	 *       .hash_func = rte_jhash,
	 *       .socket_id = rte_socket_id(),
	 *       .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
	 *   };
	 *   shm->sessions_v4 = rte_hash_create(&params);
	 *
	 * TODO: Create rte_lpm for address book
	 * TODO: Allocate array tables (zone_configs, policy_rules, etc.)
	 * TODO: Create event ring
	 */

	/* Allocate array tables */
	shm->zone_configs = rte_zmalloc("zone_configs",
		sizeof(struct zone_config) * MAX_ZONES, RTE_CACHE_LINE_SIZE);
	shm->policy_rules = rte_zmalloc("policy_rules",
		sizeof(struct policy_rule) * MAX_POLICIES * MAX_RULES_PER_POLICY,
		RTE_CACHE_LINE_SIZE);
	shm->screen_configs = rte_zmalloc("screen_configs",
		sizeof(struct screen_config) * MAX_SCREEN_PROFILES,
		RTE_CACHE_LINE_SIZE);
	shm->nat_pool_configs = rte_zmalloc("nat_pool_configs",
		sizeof(struct nat_pool_config) * MAX_NAT_POOLS,
		RTE_CACHE_LINE_SIZE);
	shm->nat64_configs = rte_zmalloc("nat64_configs",
		sizeof(struct nat64_config) * MAX_NAT64_PREFIXES,
		RTE_CACHE_LINE_SIZE);
	shm->filter_configs = rte_zmalloc("filter_configs",
		sizeof(struct filter_config) * MAX_FILTER_CONFIGS,
		RTE_CACHE_LINE_SIZE);
	shm->filter_rules = rte_zmalloc("filter_rules",
		sizeof(struct filter_rule) * MAX_FILTER_RULES,
		RTE_CACHE_LINE_SIZE);
	shm->flow_config = rte_zmalloc("flow_config",
		sizeof(struct flow_config), RTE_CACHE_LINE_SIZE);
	shm->flow_timeouts = rte_zmalloc("flow_timeouts",
		sizeof(uint32_t) * FLOW_TIMEOUT_MAX, RTE_CACHE_LINE_SIZE);
	shm->default_policy = rte_zmalloc("default_policy",
		sizeof(uint8_t), RTE_CACHE_LINE_SIZE);
	shm->fib_gen = rte_zmalloc("fib_gen",
		sizeof(uint32_t), RTE_CACHE_LINE_SIZE);

	/* Event ring for worker -> Go communication */
	shm->event_ring = rte_ring_create("events", EVENT_RING_SIZE,
		rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

	if (!shm->zone_configs || !shm->policy_rules || !shm->screen_configs ||
	    !shm->filter_configs || !shm->filter_rules || !shm->flow_config ||
	    !shm->flow_timeouts || !shm->default_policy || !shm->fib_gen ||
	    !shm->event_ring) {
		fprintf(stderr, "Failed to allocate shared memory tables\n");
		return -1;
	}

	return 0;
}

/* ============================================================
 * Per-lcore counter allocation
 * ============================================================ */

int
counters_alloc(struct pipeline_ctx *ctx)
{
	struct lcore_counters *lc;

	lc = rte_zmalloc_socket("lcore_counters", sizeof(*lc),
	                        RTE_CACHE_LINE_SIZE,
	                        rte_lcore_to_socket_id(ctx->lcore_id));
	if (!lc)
		return -1;

	ctx->policy_counters    = lc->policy_counters;
	ctx->zone_counters      = lc->zone_counters;
	ctx->interface_counters = lc->interface_counters;
	ctx->global_counters    = lc->global_counters;
	ctx->filter_counters    = lc->filter_counters;
	ctx->nat_rule_counters  = lc->nat_rule_counters;
	ctx->flood_states       = lc->flood_states;

	lcore_counter_array[ctx->lcore_id] = lc;

	return 0;
}

/* ============================================================
 * Counter aggregation (called from Go via CGo)
 * ============================================================ */

uint64_t
counters_aggregate_global(uint32_t idx)
{
	uint64_t total = 0;

	if (idx >= GLOBAL_CTR_MAX)
		return 0;

	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (lcore_counter_array[i])
			total += lcore_counter_array[i]->global_counters[idx];
	}
	return total;
}

void
counters_aggregate_policy(uint32_t policy_id,
                          uint64_t *packets, uint64_t *bytes)
{
	*packets = *bytes = 0;
	if (policy_id >= MAX_POLICIES)
		return;

	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (!lcore_counter_array[i])
			continue;
		*packets += lcore_counter_array[i]->policy_counters[policy_id].packets;
		*bytes   += lcore_counter_array[i]->policy_counters[policy_id].bytes;
	}
}

void
counters_aggregate_zone(uint32_t zone_id, uint8_t direction,
                        uint64_t *packets, uint64_t *bytes)
{
	uint32_t idx = zone_id * 2 + direction;
	*packets = *bytes = 0;
	if (idx >= MAX_ZONES * 2)
		return;

	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (!lcore_counter_array[i])
			continue;
		*packets += lcore_counter_array[i]->zone_counters[idx].packets;
		*bytes   += lcore_counter_array[i]->zone_counters[idx].bytes;
	}
}

void
counters_aggregate_iface(uint32_t ifindex,
                         uint64_t *rx_pkts, uint64_t *rx_bytes,
                         uint64_t *tx_pkts, uint64_t *tx_bytes)
{
	*rx_pkts = *rx_bytes = *tx_pkts = *tx_bytes = 0;
	if (ifindex >= MAX_INTERFACES)
		return;

	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (!lcore_counter_array[i])
			continue;
		*rx_pkts  += lcore_counter_array[i]->interface_counters[ifindex].rx_packets;
		*rx_bytes += lcore_counter_array[i]->interface_counters[ifindex].rx_bytes;
		*tx_pkts  += lcore_counter_array[i]->interface_counters[ifindex].tx_packets;
		*tx_bytes += lcore_counter_array[i]->interface_counters[ifindex].tx_bytes;
	}
}

void
counters_aggregate_filter(uint32_t rule_idx,
                          uint64_t *packets, uint64_t *bytes)
{
	*packets = *bytes = 0;
	if (rule_idx >= MAX_FILTER_RULES)
		return;

	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (!lcore_counter_array[i])
			continue;
		*packets += lcore_counter_array[i]->filter_counters[rule_idx].packets;
		*bytes   += lcore_counter_array[i]->filter_counters[rule_idx].bytes;
	}
}

void
counters_aggregate_nat_rule(uint32_t counter_id,
                            uint64_t *packets, uint64_t *bytes)
{
	*packets = *bytes = 0;
	if (counter_id >= MAX_NAT_RULE_COUNTERS)
		return;

	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (!lcore_counter_array[i])
			continue;
		*packets += lcore_counter_array[i]->nat_rule_counters[counter_id].packets;
		*bytes   += lcore_counter_array[i]->nat_rule_counters[counter_id].bytes;
	}
}

void
counters_clear_all(void)
{
	for (unsigned i = 0; i < MAX_LCORES; i++) {
		if (lcore_counter_array[i])
			memset(lcore_counter_array[i], 0, sizeof(struct lcore_counters));
	}
}

/* ============================================================
 * Per-lcore main function
 * ============================================================ */

static int
lcore_main(void *arg)
{
	struct lcore_conf *conf = arg;
	rx_loop_fn loop;

	if (conf->rx_mode >= sizeof(rx_loops) / sizeof(rx_loops[0])) {
		fprintf(stderr, "lcore %u: invalid rx_mode %u\n",
		        rte_lcore_id(), conf->rx_mode);
		return -1;
	}

	loop = rx_loops[conf->rx_mode];

	printf("lcore %u: starting with rx_mode=%u, %u ports\n",
	       rte_lcore_id(), conf->rx_mode, conf->n_ports);

	loop(conf);

	printf("lcore %u: exiting\n", rte_lcore_id());
	return 0;
}

/* ============================================================
 * Main entry point
 * ============================================================ */

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nb_ports;
	uint16_t port_id;
	unsigned lcore_id;

	/* Signal handlers */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");
	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports found\n");

	printf("Found %u DPDK ports\n", nb_ports);

	/* Create mbuf pool */
	g_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
		8192 * nb_ports, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (!g_pktmbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Allocate shared memory */
	g_shm = shm_alloc();
	if (!g_shm)
		rte_exit(EXIT_FAILURE, "Cannot allocate shared memory\n");

	/* Initialize ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		ret = port_init(port_id, g_pktmbuf_pool, 1, 1);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %u\n", port_id);
		printf("Port %u initialized\n", port_id);
	}

	/* TODO: Map ports to lcores based on configuration.
	 * For now, assign ports round-robin to worker lcores. */

	unsigned worker_idx = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		struct lcore_conf *conf = &g_lcore_conf[lcore_id];
		struct pipeline_ctx *ctx;

		ctx = rte_zmalloc_socket("pipeline_ctx", sizeof(*ctx),
		                         RTE_CACHE_LINE_SIZE,
		                         rte_lcore_to_socket_id(lcore_id));
		if (!ctx)
			rte_exit(EXIT_FAILURE, "Cannot alloc pipeline_ctx for lcore %u\n",
			         lcore_id);

		ctx->shm = g_shm;
		ctx->lcore_id = lcore_id;

		if (counters_alloc(ctx) < 0)
			rte_exit(EXIT_FAILURE, "Cannot alloc counters for lcore %u\n",
			         lcore_id);

		conf->ctx = ctx;
		conf->rx_mode = g_shm->rx_mode;

		/* Assign port(s) to this lcore */
		if (worker_idx < nb_ports) {
			conf->ports[0].port_id = worker_idx;
			conf->ports[0].queue_id = 0;
			conf->n_ports = 1;
		}
		worker_idx++;
	}

	/* Launch worker lcores */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (g_lcore_conf[lcore_id].n_ports > 0) {
			rte_eal_remote_launch(lcore_main,
			                     &g_lcore_conf[lcore_id],
			                     lcore_id);
		}
	}

	printf("DPDK worker started, waiting for shutdown signal...\n");

	/* Main lcore waits for all workers */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
	}

	/* Cleanup */
	RTE_ETH_FOREACH_DEV(port_id) {
		printf("Stopping port %u...\n", port_id);
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
	}

	rte_eal_cleanup();
	printf("DPDK worker shutdown complete\n");

	return 0;
}
