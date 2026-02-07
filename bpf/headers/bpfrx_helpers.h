#ifndef __BPFRX_HELPERS_H__
#define __BPFRX_HELPERS_H__

#include "bpfrx_common.h"

/* ============================================================
 * Packet parsing helpers
 * ============================================================ */

/* VLAN header for 802.1Q */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/*
 * Parse Ethernet header, handling one level of VLAN tagging.
 * Returns the EtherType of the inner protocol and updates l3_offset.
 */
static __always_inline int
parse_ethhdr(void *data, void *data_end, __u16 *l3_offset, __u16 *eth_proto)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;

	*eth_proto = bpf_ntohs(eth->h_proto);
	*l3_offset = sizeof(struct ethhdr);

	/* Handle one level of VLAN */
	if (*eth_proto == ETH_P_8021Q || *eth_proto == ETH_P_8021AD) {
		struct vlan_hdr *vlan = data + sizeof(struct ethhdr);
		if ((void *)(vlan + 1) > data_end)
			return -1;
		*eth_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		*l3_offset += sizeof(struct vlan_hdr);
	}

	return 0;
}

/*
 * Parse IPv4 header. Validates version and IHL.
 * Returns 0 on success, populates meta fields.
 */
static __always_inline int
parse_iphdr(void *data, void *data_end, struct pkt_meta *meta)
{
	struct iphdr *iph = data + meta->l3_offset;

	if ((void *)(iph + 1) > data_end)
		return -1;

	if (iph->version != 4)
		return -1;

	__u32 ihl = iph->ihl * 4;
	if (ihl < 20)
		return -1;
	if ((void *)iph + ihl > data_end)
		return -1;

	meta->src_ip    = iph->saddr;
	meta->dst_ip    = iph->daddr;
	meta->protocol  = iph->protocol;
	meta->ip_ttl    = iph->ttl;
	meta->l4_offset = meta->l3_offset + ihl;
	meta->pkt_len   = bpf_ntohs(iph->tot_len);
	meta->addr_family = 2; /* AF_INET */

	/* Fragmentation check */
	__u16 frag_off = bpf_ntohs(iph->frag_off);
	meta->is_fragment = (frag_off & 0x2000) || (frag_off & 0x1FFF);

	return 0;
}

/*
 * Parse L4 header (TCP, UDP, or ICMP).
 * Returns 0 on success.
 */
static __always_inline int
parse_l4hdr(void *data, void *data_end, struct pkt_meta *meta)
{
	void *l4 = data + meta->l4_offset;

	switch (meta->protocol) {
	case PROTO_TCP: {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return -1;
		meta->src_port = tcp->source;
		meta->dst_port = tcp->dest;
		meta->tcp_flags = ((__u8 *)tcp)[13];
		meta->payload_offset = meta->l4_offset + tcp->doff * 4;
		break;
	}
	case PROTO_UDP: {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return -1;
		meta->src_port = udp->source;
		meta->dst_port = udp->dest;
		meta->payload_offset = meta->l4_offset + sizeof(struct udphdr);
		break;
	}
	case PROTO_ICMP: {
		struct icmphdr *icmp = l4;
		if ((void *)(icmp + 1) > data_end)
			return -1;
		meta->icmp_type = icmp->type;
		meta->icmp_code = icmp->code;
		meta->icmp_id   = icmp->un.echo.id;
		meta->src_port  = icmp->un.echo.id; /* use as port for CT */
		meta->dst_port  = 0;
		meta->payload_offset = meta->l4_offset + sizeof(struct icmphdr);
		break;
	}
	default:
		meta->payload_offset = meta->l4_offset;
		break;
	}

	return 0;
}

/* ============================================================
 * Checksum helpers
 * ============================================================ */

/*
 * Incremental checksum update (RFC 1624) for a 4-byte field change.
 */
static __always_inline void
csum_update_4(__sum16 *csum, __be32 old_val, __be32 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~bpf_ntohl(old_val) & 0xFFFF;
	sum += ~(bpf_ntohl(old_val) >> 16) & 0xFFFF;
	sum += bpf_ntohl(new_val) & 0xFFFF;
	sum += (bpf_ntohl(new_val) >> 16) & 0xFFFF;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/*
 * Incremental checksum update for a 2-byte field change.
 */
static __always_inline void
csum_update_2(__sum16 *csum, __be16 old_val, __be16 new_val)
{
	__u32 sum;

	sum = ~((__u32)bpf_ntohs(*csum)) & 0xFFFF;
	sum += ~((__u32)bpf_ntohs(old_val)) & 0xFFFF;
	sum += (__u32)bpf_ntohs(new_val);
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = bpf_htons(~sum & 0xFFFF);
}

/* ============================================================
 * Global counter increment helper
 * ============================================================ */

static __always_inline void
inc_counter(__u32 ctr_idx)
{
	__u64 *ctr = bpf_map_lookup_elem(&global_counters, &ctr_idx);
	if (ctr)
		__sync_fetch_and_add(ctr, 1);
}

#endif /* __BPFRX_HELPERS_H__ */
