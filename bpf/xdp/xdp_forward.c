// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP forwarding stage.
 *
 * Rewrites Ethernet MAC addresses based on FIB lookup results,
 * decrements TTL, and redirects the packet to the egress interface
 * via XDP_REDIRECT through the devmap.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("xdp")
int xdp_forward_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/*
	 * If no egress interface was resolved, or it's the same as
	 * ingress (locally destined), pass to kernel stack.
	 */
	if (meta->fwd_ifindex == 0)
		return XDP_PASS;

	/* Rewrite Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;

	__builtin_memcpy(eth->h_dest, meta->fwd_dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, meta->fwd_smac, ETH_ALEN);

	/* Decrement TTL */
	struct iphdr *iph = data + meta->l3_offset;
	if ((void *)(iph + 1) > data_end)
		return XDP_DROP;

	if (iph->ttl <= 1) {
		/* TTL expired -- let kernel send ICMP Time Exceeded */
		return XDP_PASS;
	}

	/* Incremental IP checksum update for TTL change */
	__u16 old_ttl_proto = *(__u16 *)&iph->ttl;
	iph->ttl--;
	__u16 new_ttl_proto = *(__u16 *)&iph->ttl;

	csum_update_2(&iph->check, old_ttl_proto, new_ttl_proto);

	/* Increment TX counter */
	inc_counter(GLOBAL_CTR_TX_PACKETS);

	/* Redirect via devmap to egress interface */
	return bpf_redirect_map(&tx_ports, meta->fwd_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
