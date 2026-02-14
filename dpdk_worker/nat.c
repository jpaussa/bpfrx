/* SPDX-License-Identifier: GPL-2.0-or-later
 * nat.c — NAT rewrite (replaces xdp_nat).
 *
 * Performs SNAT/DNAT IP and port rewriting, pool port allocation,
 * and incremental checksum updates.
 */

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * nat_rewrite — Apply NAT translations to the packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (nat_src_ip/port, nat_dst_ip/port set)
 * @ctx:  Pipeline context
 *
 * Rewrites source and/or destination IP and port based on meta->nat_flags.
 * Updates L3 and L4 checksums incrementally.
 */
void
nat_rewrite(struct rte_mbuf *pkt, struct pkt_meta *meta,
            struct pipeline_ctx *ctx)
{
	(void)pkt;
	(void)meta;
	(void)ctx;

	/* TODO: Implement NAT rewrite (matching bpf/xdp/xdp_nat.c):
	 *
	 * 1. DNAT (SESS_FLAG_DNAT):
	 *    - Replace dst_ip with meta->nat_dst_ip
	 *    - Replace dst_port with meta->nat_dst_port (if non-zero)
	 *    - Update IP checksum incrementally
	 *    - Update TCP/UDP checksum incrementally
	 *
	 * 2. SNAT (SESS_FLAG_SNAT):
	 *    - If meta->nat_src_ip is not set, allocate from NAT pool:
	 *      a. Look up SNAT rules for (ingress_zone, egress_zone)
	 *      b. Match source/dest address against rule criteria
	 *      c. Allocate port from pool (round-robin or hash-based)
	 *      d. Set meta->nat_src_ip and meta->nat_src_port
	 *    - Replace src_ip with meta->nat_src_ip
	 *    - Replace src_port with meta->nat_src_port
	 *    - Update checksums
	 *    - Create DNAT return entry for reverse traffic
	 *
	 * 3. Static 1:1 NAT (SESS_FLAG_STATIC_NAT):
	 *    - Look up in static_nat_v4 hash
	 *    - Replace IP (no port change)
	 *    - Update IP checksum
	 *
	 * 4. Incremental checksum update:
	 *    - IPv4: rte_ipv4_hdr.hdr_checksum
	 *    - TCP: rte_tcp_hdr.cksum (pseudo-header includes IPs)
	 *    - UDP: rte_udp_hdr.dgram_cksum
	 *    - Use rte_ipv4_cksum() / rte_ipv4_udptcp_cksum() for full recalc
	 *      or incremental update for single-field changes
	 *
	 * 5. Address-persistent SNAT:
	 *    - If nat_pool_config.addr_persistent is set, hash source IP
	 *      to always select the same pool IP
	 *
	 * 6. Counter update:
	 *    ctr_nat_rule_add(ctx, counter_id, pkt_len);
	 */
}
