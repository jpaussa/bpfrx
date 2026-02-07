// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP main entry point.
 *
 * Parses Ethernet/IPv4/L4 headers, populates per-CPU packet metadata,
 * and dispatches to the first pipeline stage via tail call.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

SEC("xdp")
int xdp_main_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 l3_offset, eth_proto;

	/* Parse Ethernet header */
	if (parse_ethhdr(data, data_end, &l3_offset, &eth_proto) < 0)
		return XDP_DROP;

	/* Only handle IPv4 for now */
	if (eth_proto != ETH_P_IP)
		return XDP_PASS;

	/* Get per-CPU scratch space for packet metadata */
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	__builtin_memset(meta, 0, sizeof(*meta));
	meta->l3_offset = l3_offset;
	meta->direction = 0; /* ingress */
	meta->ingress_ifindex = ctx->ingress_ifindex;

	/* Parse IPv4 header */
	if (parse_iphdr(data, data_end, meta) < 0)
		return XDP_DROP;

	/* Parse L4 header */
	if (!meta->is_fragment) {
		if (parse_l4hdr(data, data_end, meta) < 0)
			return XDP_DROP;
	}

	/* Increment global RX counter */
	inc_counter(GLOBAL_CTR_RX_PACKETS);

	/*
	 * Dispatch to pipeline.
	 *
	 * Phase 1: skip screen and conntrack, go directly to zone
	 * classification. Later phases will use XDP_PROG_SCREEN.
	 */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_ZONE);

	/* Tail call failed -- pass to kernel stack as fallback */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
