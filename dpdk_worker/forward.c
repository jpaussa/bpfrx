/* SPDX-License-Identifier: GPL-2.0-or-later
 * forward.c — Packet forwarding (replaces xdp_forward).
 *
 * FIB lookup, MAC rewrite, VLAN tag push/pop, TTL decrement,
 * and TX burst to output port.
 */

#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * forward_packet — Forward the packet to the output port.
 *
 * @pkt:  Packet mbuf (headers already modified by NAT if needed)
 * @meta: Parsed packet metadata (fwd_ifindex, fwd_dmac, fwd_smac set)
 * @ctx:  Pipeline context
 *
 * Performs FIB lookup (if not cached), MAC rewrite, VLAN handling,
 * TTL decrement, and transmits the packet.
 */
void
forward_packet(struct rte_mbuf *pkt, struct pkt_meta *meta,
               struct pipeline_ctx *ctx)
{
	(void)ctx;

	/* TODO: Implement forwarding (matching bpf/xdp/xdp_forward.c):
	 *
	 * 1. TTL check and decrement:
	 *    if (meta->ip_ttl <= 1) {
	 *        // TTL expired — should send ICMP Time Exceeded
	 *        // For now, drop
	 *        rte_pktmbuf_free(pkt);
	 *        return;
	 *    }
	 *    // Decrement TTL in packet header
	 *    if (meta->addr_family == AF_INET) {
	 *        struct rte_ipv4_hdr *ip4 = rte_pktmbuf_mtod_offset(
	 *            pkt, struct rte_ipv4_hdr *, meta->l3_offset);
	 *        ip4->time_to_live--;
	 *        // Update IPv4 checksum incrementally
	 *    } else {
	 *        struct rte_ipv6_hdr *ip6 = rte_pktmbuf_mtod_offset(
	 *            pkt, struct rte_ipv6_hdr *, meta->l3_offset);
	 *        ip6->hop_limits--;
	 *    }
	 *
	 * 2. FIB lookup (if fwd_ifindex not set from session cache):
	 *    if (meta->fwd_ifindex == 0) {
	 *        // Look up destination in FIB (userspace routing table)
	 *        // Set meta->fwd_ifindex, fwd_dmac, fwd_smac
	 *        // TODO: Implement userspace FIB (rte_fib or rte_lpm)
	 *    }
	 *
	 * 3. MAC rewrite:
	 *    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt,
	 *        struct rte_ether_hdr *);
	 *    rte_ether_addr_copy((struct rte_ether_addr *)meta->fwd_dmac,
	 *                        &eth->dst_addr);
	 *    rte_ether_addr_copy((struct rte_ether_addr *)meta->fwd_smac,
	 *                        &eth->src_addr);
	 *
	 * 4. VLAN handling:
	 *    if (meta->egress_vlan_id != 0) {
	 *        // Push VLAN tag (or modify existing)
	 *        // Insert 4 bytes of 802.1Q header
	 *    } else if (meta->ingress_vlan_id != 0) {
	 *        // Strip VLAN tag if present on output
	 *    }
	 *
	 * 5. DSCP rewrite (if set by firewall filter):
	 *    if (meta->dscp_rewrite != 0xFF) {
	 *        // Modify TOS/traffic-class field
	 *    }
	 *
	 * 6. TCP MSS clamping (for IPsec/GRE):
	 *    // Check flow_config for MSS limits
	 *    // If TCP SYN and MSS option > limit, clamp it
	 *
	 * 7. Transmit:
	 *    uint16_t tx_port = meta->fwd_ifindex;  // Map ifindex to DPDK port_id
	 *    uint16_t sent = rte_eth_tx_burst(tx_port, 0, &pkt, 1);
	 *    if (sent == 0) {
	 *        rte_pktmbuf_free(pkt);
	 *        // Increment drop counter
	 *    } else {
	 *        ctr_iface_tx_add(ctx, tx_port, rte_pktmbuf_pkt_len(pkt));
	 *    }
	 */

	/* Stub: drop packet (no forwarding table configured) */
	(void)meta;
	rte_pktmbuf_free(pkt);
}
