/* SPDX-License-Identifier: GPL-2.0-or-later
 * nat64.c — NAT64 IPv6 <-> IPv4 translation (replaces xdp_nat64).
 *
 * Translates IPv6 packets with a NAT64 prefix destination to IPv4,
 * and reverse-translates IPv4 replies back to IPv6.
 */

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_hash.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * nat64_translate — Perform NAT64 header translation.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata
 * @ctx:  Pipeline context
 *
 * For IPv6->IPv4 (forward):
 *   - Strip IPv6 header, create IPv4 header
 *   - Extract embedded IPv4 address from NAT64 prefix (last 32 bits)
 *   - SNAT with pool address
 *   - Create nat64_state reverse entry for return traffic
 *
 * For IPv4->IPv6 (reverse):
 *   - Look up nat64_state by IPv4 5-tuple
 *   - Strip IPv4 header, create IPv6 header
 *   - Restore original IPv6 addresses from state
 */
void
nat64_translate(struct rte_mbuf *pkt, struct pkt_meta *meta,
                struct pipeline_ctx *ctx)
{
	(void)pkt;
	(void)meta;
	(void)ctx;

	/* TODO: Implement NAT64 translation (matching bpf/xdp/xdp_nat64.c):
	 *
	 * IPv6 -> IPv4 direction:
	 *
	 * 1. Verify destination matches a NAT64 prefix:
	 *    struct nat64_prefix_key pk;
	 *    memcpy(pk.prefix, meta->dst_ip.v6, 12);  // first 96 bits
	 *    int pos = rte_hash_lookup(ctx->shm->nat64_prefix_map, &pk);
	 *    if (pos < 0) return;  // Not a NAT64 destination
	 *
	 * 2. Extract embedded IPv4 address (last 32 bits of IPv6 dst):
	 *    uint32_t dst_v4 = *(uint32_t *)(meta->dst_ip.v6 + 12);
	 *
	 * 3. Allocate SNAT IPv4 address from pool:
	 *    - Use nat64_config.snat_pool_id to find pool
	 *    - Allocate port from pool
	 *
	 * 4. Transform packet:
	 *    - Remove IPv6 header (40 bytes)
	 *    - Prepend IPv4 header (20 bytes) — net shrink of 20 bytes
	 *    - Set IPv4 src = allocated pool IP
	 *    - Set IPv4 dst = extracted v4 address
	 *    - Translate hop_limit -> TTL
	 *    - Translate next_header -> protocol
	 *    - Compute IPv4 checksum
	 *    - Recompute L4 checksum (pseudo-header changed)
	 *
	 * 5. Create nat64_state reverse entry:
	 *    struct nat64_state_key sk = {
	 *        .src_ip = dst_v4,
	 *        .dst_ip = snat_ip,
	 *        .src_port = meta->dst_port,
	 *        .dst_port = snat_port,
	 *        .protocol = meta->protocol,
	 *    };
	 *    struct nat64_state_value sv = {
	 *        .orig_src_v6 = meta->src_ip.v6,
	 *        .orig_dst_v6 = meta->dst_ip.v6,
	 *        .orig_src_port = meta->src_port,
	 *        .orig_dst_port = meta->dst_port,
	 *    };
	 *
	 * IPv4 -> IPv6 direction (reverse):
	 *
	 * 1. Look up nat64_state by IPv4 5-tuple
	 * 2. Remove IPv4 header, prepend IPv6 header
	 * 3. Restore original IPv6 addresses from state
	 * 4. Recompute checksums
	 */
}
