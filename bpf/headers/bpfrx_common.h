#ifndef __BPFRX_COMMON_H__
#define __BPFRX_COMMON_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ============================================================
 * Network header definitions for BPF programs.
 * We define these directly to avoid pulling in userspace headers
 * (linux/icmp.h -> linux/if.h -> sys/socket.h) which don't
 * compile under BPF cross-compilation.
 * ============================================================ */

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8  ihl:4, version:4;
#else
	__u8  version:4, ihl:4;
#endif
	__u8  tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8  ttl;
	__u8  protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u16 res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#else
	__u16 doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct icmphdr {
	__u8  type;
	__u8  code;
	__sum16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
	} un;
};

/* ============================================================
 * Constants
 * ============================================================ */

/* Maximum values */
#define MAX_ZONES              64
#define MAX_INTERFACES         256
#define MAX_POLICIES           4096
#define MAX_RULES_PER_POLICY   256
#define MAX_SESSIONS           1048576  /* 1M sessions */
#define MAX_NAT_POOLS          32
#define MAX_NAT_POOL_IPS       256
#define MAX_ADDRESSES          8192
#define MAX_APPLICATIONS       1024
#define MAX_SCREEN_PROFILES    64
#define MAX_PORT_SCAN_TRACK    65536

/* XDP tail call program indices */
#define XDP_PROG_SCREEN        0
#define XDP_PROG_ZONE          1
#define XDP_PROG_CONNTRACK     2
#define XDP_PROG_POLICY        3
#define XDP_PROG_NAT           4
#define XDP_PROG_FORWARD       5
#define XDP_PROG_MAX           6

/* TC tail call program indices */
#define TC_PROG_CONNTRACK      0
#define TC_PROG_NAT            1
#define TC_PROG_SCREEN_EGRESS  2
#define TC_PROG_FORWARD        3
#define TC_PROG_MAX            4

/* Session states */
#define SESS_STATE_NONE        0
#define SESS_STATE_NEW         1
#define SESS_STATE_SYN_SENT    2
#define SESS_STATE_SYN_RECV    3
#define SESS_STATE_ESTABLISHED 4
#define SESS_STATE_FIN_WAIT    5
#define SESS_STATE_CLOSE_WAIT  6
#define SESS_STATE_TIME_WAIT   7
#define SESS_STATE_CLOSED      8

/* Session flags */
#define SESS_FLAG_SNAT         (1 << 0)
#define SESS_FLAG_DNAT         (1 << 1)
#define SESS_FLAG_LOG          (1 << 2)
#define SESS_FLAG_COUNT        (1 << 3)
#define SESS_FLAG_ALG          (1 << 4)
#define SESS_FLAG_PREDICTED    (1 << 5)
#define SESS_FLAG_STATIC_NAT   (1 << 6)

/* Policy actions */
#define ACTION_DENY            0
#define ACTION_PERMIT          1
#define ACTION_REJECT          2

/* Protocol numbers */
#define PROTO_TCP              6
#define PROTO_UDP              17
#define PROTO_ICMP             1

/* Event types for ring buffer */
#define EVENT_TYPE_SESSION_OPEN   1
#define EVENT_TYPE_SESSION_CLOSE  2
#define EVENT_TYPE_POLICY_DENY    3
#define EVENT_TYPE_SCREEN_DROP    4
#define EVENT_TYPE_ALG_REQUEST    5

/* Global counter indices */
#define GLOBAL_CTR_RX_PACKETS      0
#define GLOBAL_CTR_TX_PACKETS      1
#define GLOBAL_CTR_DROPS           2
#define GLOBAL_CTR_SESSIONS_NEW    3
#define GLOBAL_CTR_SESSIONS_CLOSED 4
#define GLOBAL_CTR_SCREEN_DROPS    5
#define GLOBAL_CTR_POLICY_DENY     6
#define GLOBAL_CTR_NAT_ALLOC_FAIL  7
#define GLOBAL_CTR_MAX             8

/* Screen option flags */
#define SCREEN_SYN_FLOOD         (1 << 0)
#define SCREEN_ICMP_FLOOD        (1 << 1)
#define SCREEN_UDP_FLOOD         (1 << 2)
#define SCREEN_PORT_SCAN         (1 << 3)
#define SCREEN_IP_SWEEP          (1 << 4)
#define SCREEN_LAND_ATTACK       (1 << 5)
#define SCREEN_PING_OF_DEATH     (1 << 6)
#define SCREEN_TEAR_DROP         (1 << 7)
#define SCREEN_TCP_SYN_FIN       (1 << 8)
#define SCREEN_TCP_NO_FLAG       (1 << 9)
#define SCREEN_TCP_FIN_NO_ACK    (1 << 10)
#define SCREEN_WINNUKE           (1 << 11)
#define SCREEN_IP_SOURCE_ROUTE   (1 << 12)

/* ============================================================
 * Packet metadata -- passed between tail call stages via
 * per-CPU scratch map at index 0.
 * ============================================================ */

struct pkt_meta {
	/* Parsed header fields (network byte order for IPs/ports) */
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8   protocol;
	__u8   tcp_flags;
	__u8   ip_ttl;
	__u8   pad0;

	/* ICMP specific */
	__be16 icmp_id;
	__u8   icmp_type;
	__u8   icmp_code;

	/* Header offsets from packet start */
	__u16 l3_offset;
	__u16 l4_offset;
	__u16 payload_offset;
	__u16 pkt_len;

	/* Zone classification */
	__u16 ingress_zone;
	__u16 egress_zone;
	__u32 ingress_ifindex;

	/* Pipeline state */
	__u8  direction;    /* 0=ingress, 1=egress */
	__u8  addr_family;  /* AF_INET=2 */
	__u8  is_fragment;
	__u8  ct_state;     /* SESS_STATE_* */
	__u8  ct_direction; /* 0=forward, 1=reverse */
	__u8  pad1[3];

	__u32 policy_id;

	/* NAT translations to apply */
	__be32 nat_src_ip;
	__be32 nat_dst_ip;
	__be16 nat_src_port;
	__be16 nat_dst_port;
	__u32  nat_flags;

	/* Forwarding decision */
	__u32 fwd_ifindex;
	__u8  fwd_dmac[ETH_ALEN];
	__u8  fwd_smac[ETH_ALEN];
};

/* ============================================================
 * Event structure for ring buffer
 * ============================================================ */

struct event {
	__u64  timestamp;
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u32  policy_id;
	__u16  ingress_zone;
	__u16  egress_zone;
	__u8   event_type;
	__u8   protocol;
	__u8   action;
	__u8   pad;
	__u64  session_packets;
	__u64  session_bytes;
};

/* ============================================================
 * Zone configuration
 * ============================================================ */

struct zone_config {
	__u16 zone_id;
	__u16 screen_profile_id;
	__u32 host_inbound_flags;
};

/* ============================================================
 * Counter value (per-CPU)
 * ============================================================ */

struct counter_value {
	__u64 packets;
	__u64 bytes;
};

#endif /* __BPFRX_COMMON_H__ */
