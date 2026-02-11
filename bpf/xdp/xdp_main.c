// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP main entry point.
 *
 * Parses Ethernet/IPv4/IPv6/L4 headers, populates per-CPU packet metadata,
 * and dispatches to the first pipeline stage via tail call.
 */

#include "../headers/bpfrx_common.h"
#define BPFRX_NAT_POOLS
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"
#include "../headers/bpfrx_trace.h"

SEC("xdp")
int xdp_main_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 l3_offset, eth_proto, vlan_id = 0;

	/* Parse Ethernet header (extracts VLAN ID if present) */
	if (parse_ethhdr(data, data_end, &l3_offset, &eth_proto, &vlan_id) < 0)
		return XDP_DROP;

	/* Get per-CPU scratch space for packet metadata */
	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	/* Zero from src_port onward — skip src_ip/dst_ip (32 bytes)
	 * which the L3 parser always overwrites. */
	__builtin_memset((__u8 *)meta + 32, 0, sizeof(*meta) - 32);
	meta->direction = 0; /* ingress */
	meta->ingress_ifindex = ctx->ingress_ifindex;
	meta->ingress_vlan_id = vlan_id;

	/* Strip VLAN tag if present so pipeline sees plain Ethernet */
	if (vlan_id != 0) {
		if (xdp_vlan_tag_pop(ctx) < 0)
			return XDP_DROP;
		/* Re-read pointers after adjust_head */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		l3_offset = sizeof(struct ethhdr);
	}

	meta->l3_offset = l3_offset;

	/* Parse L3 header based on EtherType */
	if (eth_proto == ETH_P_IP) {
		if (parse_iphdr(data, data_end, meta) < 0)
			return XDP_DROP;
	} else if (eth_proto == 0x86DD) { /* ETH_P_IPV6 */
		if (parse_ipv6hdr(data, data_end, meta) < 0)
			return XDP_DROP;
	} else {
		/* Non-IP traffic (ARP, etc.) — pass to kernel.
		 * Restore VLAN tag so kernel delivers to sub-interface. */
		if (vlan_id != 0) {
			if (xdp_vlan_tag_push(ctx, vlan_id) < 0)
				return XDP_DROP;
		}
		return XDP_PASS;
	}

	/* Parse L4 header */
	if (!meta->is_fragment) {
		if (parse_l4hdr(data, data_end, meta) < 0)
			return XDP_DROP;
	}

	/* Evaluate firewall filter (if assigned to this interface) */
	int filt_rc = evaluate_firewall_filter(meta);
	if (filt_rc < 0)
		return XDP_DROP;  /* discard or reject */

	/* Increment global RX counter and per-interface RX counter */
	inc_counter(GLOBAL_CTR_RX_PACKETS);
	inc_iface_rx(meta->ingress_ifindex, meta->pkt_len);

	TRACE_XDP_MAIN(meta);

	/* Dispatch to pipeline: screen -> zone -> conntrack -> policy -> nat -> forward */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_SCREEN);

	/* Tail call failed -- pass to kernel stack as fallback */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
