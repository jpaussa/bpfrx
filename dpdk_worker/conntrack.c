/* SPDX-License-Identifier: GPL-2.0-or-later
 * conntrack.c — Connection tracking (replaces xdp_conntrack).
 *
 * Session hash lookup/insert with dual entries (forward + reverse),
 * TCP state tracking, and timeout management.
 */

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_cycles.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/* Conntrack result codes */
#define CT_NEW         0
#define CT_ESTABLISHED 1
#define CT_INVALID     2

/**
 * ct_tcp_update_state — TCP state machine transition.
 *
 * Matches the BPF implementation in bpfrx_conntrack.h exactly.
 */
static inline uint8_t
ct_tcp_update_state(uint8_t current_state, uint8_t tcp_flags, uint8_t direction)
{
	uint8_t syn = tcp_flags & 0x02;
	uint8_t ack = tcp_flags & 0x10;
	uint8_t fin = tcp_flags & 0x01;
	uint8_t rst = tcp_flags & 0x04;

	if (rst)
		return SESS_STATE_CLOSED;

	switch (current_state) {
	case SESS_STATE_NEW:
		if (direction == 0 && syn && !ack)
			return SESS_STATE_SYN_SENT;
		break;
	case SESS_STATE_SYN_SENT:
		if (direction == 1 && syn && ack)
			return SESS_STATE_SYN_RECV;
		break;
	case SESS_STATE_SYN_RECV:
		if (direction == 0 && ack)
			return SESS_STATE_ESTABLISHED;
		break;
	case SESS_STATE_ESTABLISHED:
		if (fin)
			return SESS_STATE_FIN_WAIT;
		break;
	case SESS_STATE_FIN_WAIT:
		if (fin)
			return SESS_STATE_CLOSE_WAIT;
		break;
	case SESS_STATE_CLOSE_WAIT:
		if (ack)
			return SESS_STATE_TIME_WAIT;
		break;
	}

	return current_state;
}

/**
 * conntrack_lookup — Look up an existing session for this packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata
 * @ctx:  Pipeline context
 *
 * Returns:
 *   CT_ESTABLISHED — Session found and updated (fast path)
 *   CT_NEW         — No session found (needs policy check)
 *   CT_INVALID     — Session found but in invalid state
 *
 * On CT_ESTABLISHED, meta->ct_state, ct_direction, nat_flags,
 * nat_src/dst, policy_id are populated from the session.
 */
int
conntrack_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
                 struct pipeline_ctx *ctx)
{
	(void)pkt;

	/* TODO: Implement session lookup:
	 *
	 * 1. Build session_key from meta (src_ip, dst_ip, src_port, dst_port, proto)
	 *
	 * 2. Look up in sessions hash:
	 *    struct session_key sk = {
	 *        .src_ip = meta->src_ip.v4,
	 *        .dst_ip = meta->dst_ip.v4,
	 *        .src_port = meta->src_port,
	 *        .dst_port = meta->dst_port,
	 *        .protocol = meta->protocol,
	 *    };
	 *    int pos = rte_hash_lookup(ctx->shm->sessions_v4, &sk);
	 *
	 * 3. If found:
	 *    struct session_value *sv = &ctx->shm->session_values_v4[pos];
	 *    - Update sv->last_seen to current time
	 *    - Update TCP state via ct_tcp_update_state() if TCP
	 *    - Update forward/reverse counters
	 *    - Copy NAT info to meta (nat_src_ip, nat_dst_ip, nat_flags, etc.)
	 *    - Set meta->ct_state, ct_direction, policy_id
	 *    - Check FIB cache validity (sv->fib_gen == *ctx->shm->fib_gen)
	 *    - If FIB cache valid, copy fib_ifindex/dmac/smac to meta
	 *    - Return CT_ESTABLISHED
	 *
	 * 4. If not found, try reverse key (swap src/dst):
	 *    - If reverse found: ct_direction = 1, same update logic
	 *    - Return CT_ESTABLISHED
	 *
	 * 5. For IPv6: use sessions_v6 with session_key_v6
	 *
	 * 6. If neither found: return CT_NEW
	 */

	(void)ctx;
	return CT_NEW;
}

/**
 * conntrack_create — Create a new session (forward + reverse entries).
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (policy_id, NAT info already set)
 * @ctx:  Pipeline context
 *
 * Returns 0 on success, -1 on failure (table full).
 *
 * Creates dual entries in the session hash:
 *   Forward:  (src, dst, sport, dport, proto) -> session_value
 *   Reverse:  (dst, src, dport, sport, proto) -> session_value (is_reverse=1)
 */
int
conntrack_create(struct rte_mbuf *pkt, struct pkt_meta *meta,
                 struct pipeline_ctx *ctx)
{
	(void)pkt;

	/* TODO: Implement session creation:
	 *
	 * 1. Build forward session_key from meta
	 *
	 * 2. Populate session_value:
	 *    - state = SESS_STATE_NEW (or SYN_SENT for TCP SYN)
	 *    - flags = meta->nat_flags
	 *    - created = last_seen = current timestamp (seconds since boot)
	 *    - timeout = ct_get_timeout_default(meta->protocol, state)
	 *    - policy_id = meta->policy_id
	 *    - ingress_zone = meta->ingress_zone
	 *    - egress_zone = meta->egress_zone
	 *    - NAT fields from meta
	 *    - Build and store reverse_key
	 *
	 * 3. Insert forward entry:
	 *    int pos = rte_hash_add_key(ctx->shm->sessions_v4, &fwd_key);
	 *    ctx->shm->session_values_v4[pos] = fwd_val;
	 *
	 * 4. Build and insert reverse entry:
	 *    reverse_key = {dst, src, dport, sport, proto}
	 *    reverse_value = copy of fwd_val with is_reverse=1
	 *    int rpos = rte_hash_add_key(ctx->shm->sessions_v4, &rev_key);
	 *    ctx->shm->session_values_v4[rpos] = rev_val;
	 *
	 * 5. For IPv6: use sessions_v6
	 *
	 * 6. If DNAT/SNAT, create NAT return entries in dnat_table
	 */

	(void)ctx;
	(void)meta;
	return 0;
}
