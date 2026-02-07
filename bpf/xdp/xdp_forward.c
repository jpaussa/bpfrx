// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP forwarding stage.
 *
 * Rewrites Ethernet MAC addresses based on FIB lookup results,
 * decrements TTL/hop_limit, and redirects the packet to the egress
 * interface via XDP_REDIRECT through the devmap.
 * Supports both IPv4 and IPv6.
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

	if (meta->addr_family == AF_INET) {
		/* IPv4: Decrement TTL + update IP checksum */
		struct iphdr *iph = data + meta->l3_offset;
		if ((void *)(iph + 1) > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS; /* Let kernel send ICMP Time Exceeded */

		__u16 old_ttl_proto = *(__u16 *)&iph->ttl;
		iph->ttl--;
		__u16 new_ttl_proto = *(__u16 *)&iph->ttl;

		csum_update_2(&iph->check, old_ttl_proto, new_ttl_proto);
	} else {
		/* IPv6: Decrement hop_limit (no checksum update needed) */
		struct ipv6hdr *ip6h = data + meta->l3_offset;
		if ((void *)(ip6h + 1) > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS; /* Let kernel send ICMPv6 Time Exceeded */

		ip6h->hop_limit--;
	}

	/* Increment TX counter */
	inc_counter(GLOBAL_CTR_TX_PACKETS);

	/* Redirect via devmap to egress interface */
	return bpf_redirect_map(&tx_ports, meta->fwd_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
