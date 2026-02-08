// SPDX-License-Identifier: GPL-2.0
/*
 * bpfrx XDP NAT rewriting stage.
 *
 * Reconciles actual packet headers with the desired state in pkt_meta.
 * If meta->src_ip differs from the packet's saddr, rewrite saddr + fix
 * checksums. Same for dst_ip. Then tail-call to forward.
 * Supports both IPv4 and IPv6.
 */

#include "../headers/bpfrx_common.h"
#include "../headers/bpfrx_maps.h"
#include "../headers/bpfrx_helpers.h"

/*
 * Update L4 (TCP/UDP) checksum for a 4-byte pseudo-header field change.
 */
static __always_inline void
nat_update_l4_csum(void *data, void *data_end, struct pkt_meta *meta,
		   __be32 old_ip, __be32 new_ip)
{
	void *l4 = data + meta->l4_offset;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_4(&tcp->check, old_ip, new_ip);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		if (udp->check != 0)
			csum_update_4(&udp->check, old_ip, new_ip);
	}
}

/*
 * Update L4 checksum for a 128-bit IPv6 address change.
 */
static __always_inline void
nat_update_l4_csum_v6(void *data, void *data_end, struct pkt_meta *meta,
		      const __u8 *old_addr, const __u8 *new_addr)
{
	void *l4 = data + meta->l4_offset;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_16(&tcp->check, old_addr, new_addr);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		/* IPv6 UDP checksum is mandatory -- always update */
		csum_update_16(&udp->check, old_addr, new_addr);
	} else if (meta->protocol == PROTO_ICMPV6) {
		/* ICMPv6 checksum covers pseudo-header with addresses */
		struct icmp6hdr *icmp6 = l4;
		if ((void *)(icmp6 + 1) > data_end)
			return;
		csum_update_16(&icmp6->icmp6_cksum, old_addr, new_addr);
	}
}

/*
 * Update L4 checksum for a 2-byte port field change.
 */
static __always_inline void
nat_update_l4_port_csum(void *data, void *data_end, struct pkt_meta *meta,
			__be16 old_port, __be16 new_port)
{
	void *l4 = data + meta->l4_offset;

	if (meta->protocol == PROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return;
		csum_update_2(&tcp->check, old_port, new_port);
	} else if (meta->protocol == PROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return;
		if (meta->addr_family == AF_INET6 || udp->check != 0)
			csum_update_2(&udp->check, old_port, new_port);
	}
}

/*
 * IPv4 NAT rewrite.
 */
static __always_inline void
nat_rewrite_v4(void *data, void *data_end, struct pkt_meta *meta)
{
	struct iphdr *iph = data + meta->l3_offset;
	if ((void *)(iph + 1) > data_end)
		return;

	/* Source IP rewrite */
	if (meta->src_ip.v4 != iph->saddr) {
		__be32 old_src = iph->saddr;
		csum_update_4(&iph->check, old_src, meta->src_ip.v4);
		nat_update_l4_csum(data, data_end, meta, old_src, meta->src_ip.v4);
		iph->saddr = meta->src_ip.v4;
	}

	/* Source port rewrite */
	if (meta->src_port != 0) {
		void *l4 = data + meta->l4_offset;
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							udp->source, meta->src_port);
				udp->source = meta->src_port;
			}
		}
	}

	/* Destination IP rewrite */
	if (meta->dst_ip.v4 != iph->daddr) {
		__be32 old_dst = iph->daddr;
		csum_update_4(&iph->check, old_dst, meta->dst_ip.v4);
		nat_update_l4_csum(data, data_end, meta, old_dst, meta->dst_ip.v4);
		iph->daddr = meta->dst_ip.v4;
	}

	/* Destination port rewrite */
	if (meta->dst_port != 0) {
		void *l4 = data + meta->l4_offset;
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->dest != meta->dst_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							udp->dest, meta->dst_port);
				udp->dest = meta->dst_port;
			}
		}
	}

	/* ICMP echo ID rewrite */
	if (meta->protocol == PROTO_ICMP) {
		struct icmphdr *icmp = data + meta->l4_offset;
		if ((void *)(icmp + 1) <= data_end &&
		    (icmp->type == 8 || icmp->type == 0)) {
			/* Forward: use allocated port as new echo ID.
			 * Return (DNAT): dst_port holds the original echo ID. */
			__be16 desired_id = meta->src_port;
			if (meta->nat_flags & SESS_FLAG_DNAT)
				desired_id = meta->dst_port;
			if (icmp->un.echo.id != desired_id) {
				csum_update_2(&icmp->checksum,
					      icmp->un.echo.id, desired_id);
				icmp->un.echo.id = desired_id;
			}
		}
	}
}

/*
 * IPv6 NAT rewrite.
 * IPv6 has no IP header checksum. Only L4 checksums need updating.
 */
static __always_inline void
nat_rewrite_v6(void *data, void *data_end, struct pkt_meta *meta)
{
	struct ipv6hdr *ip6h = data + meta->l3_offset;
	if ((void *)(ip6h + 1) > data_end)
		return;

	/* Source IP rewrite */
	if (!ip_addr_eq_v6(meta->src_ip.v6, (__u8 *)&ip6h->saddr)) {
		__u8 old_src[16];
		__builtin_memcpy(old_src, &ip6h->saddr, 16);
		nat_update_l4_csum_v6(data, data_end, meta, old_src, meta->src_ip.v6);
		__builtin_memcpy(&ip6h->saddr, meta->src_ip.v6, 16);
	}

	/* Source port rewrite */
	if (meta->src_port != 0) {
		void *l4 = data + meta->l4_offset;
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->source != meta->src_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							tcp->source, meta->src_port);
				tcp->source = meta->src_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->source != meta->src_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							udp->source, meta->src_port);
				udp->source = meta->src_port;
			}
		}
	}

	/* Destination IP rewrite */
	if (!ip_addr_eq_v6(meta->dst_ip.v6, (__u8 *)&ip6h->daddr)) {
		__u8 old_dst[16];
		__builtin_memcpy(old_dst, &ip6h->daddr, 16);
		nat_update_l4_csum_v6(data, data_end, meta, old_dst, meta->dst_ip.v6);
		__builtin_memcpy(&ip6h->daddr, meta->dst_ip.v6, 16);
	}

	/* Destination port rewrite */
	if (meta->dst_port != 0) {
		void *l4 = data + meta->l4_offset;
		if (meta->protocol == PROTO_TCP) {
			struct tcphdr *tcp = l4;
			if ((void *)(tcp + 1) <= data_end && tcp->dest != meta->dst_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							tcp->dest, meta->dst_port);
				tcp->dest = meta->dst_port;
			}
		} else if (meta->protocol == PROTO_UDP) {
			struct udphdr *udp = l4;
			if ((void *)(udp + 1) <= data_end && udp->dest != meta->dst_port) {
				nat_update_l4_port_csum(data, data_end, meta,
							udp->dest, meta->dst_port);
				udp->dest = meta->dst_port;
			}
		}
	}

	/* ICMPv6 echo ID rewrite */
	if (meta->protocol == PROTO_ICMPV6) {
		struct icmp6hdr *icmp6 = data + meta->l4_offset;
		if ((void *)(icmp6 + 1) <= data_end &&
		    (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129)) {
			__be16 desired_id = meta->src_port;
			if (meta->nat_flags & SESS_FLAG_DNAT)
				desired_id = meta->dst_port;
			if (icmp6->un.echo.id != desired_id) {
				csum_update_2(&icmp6->icmp6_cksum,
					      icmp6->un.echo.id, desired_id);
				icmp6->un.echo.id = desired_id;
			}
		}
	}
}

SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u32 zero = 0;
	struct pkt_meta *meta = bpf_map_lookup_elem(&pkt_meta_scratch, &zero);
	if (!meta)
		return XDP_DROP;

	if (meta->addr_family == AF_INET)
		nat_rewrite_v4(data, data_end, meta);
	else
		nat_rewrite_v6(data, data_end, meta);

	/* Continue to forwarding */
	bpf_tail_call(ctx, &xdp_progs, XDP_PROG_FORWARD);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
