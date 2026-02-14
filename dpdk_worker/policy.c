/* SPDX-License-Identifier: GPL-2.0-or-later
 * policy.c — Zone-pair policy matching (replaces xdp_policy).
 *
 * Two-level lookup: (from_zone, to_zone) -> policy_set, then iterate
 * rules in the policy_set for first match. Supports address book
 * matching via LPM, application matching, and NAT rule association.
 */

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_lpm.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * policy_check — Check zone-pair policies for this packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (ingress_zone, egress_zone set)
 * @ctx:  Pipeline context
 *
 * Returns the action: ACTION_PERMIT, ACTION_DENY, or ACTION_REJECT.
 *
 * On ACTION_PERMIT, meta->policy_id and NAT fields are populated.
 */
int
policy_check(struct rte_mbuf *pkt, struct pkt_meta *meta,
             struct pipeline_ctx *ctx)
{
	(void)pkt;

	/* TODO: Implement policy matching:
	 *
	 * 1. Build zone_pair_key:
	 *    struct zone_pair_key zpk = {
	 *        .from_zone = meta->ingress_zone,
	 *        .to_zone = meta->egress_zone,
	 *    };
	 *
	 * 2. Look up zone-pair policy set:
	 *    int pos = rte_hash_lookup(ctx->shm->zone_pair_policies, &zpk);
	 *    if (pos < 0) {
	 *        // No zone-pair policy; check global policy (junos-global)
	 *        // Then fall back to default_policy
	 *        return *ctx->shm->default_policy == ACTION_PERMIT ?
	 *               ACTION_PERMIT : ACTION_DENY;
	 *    }
	 *    struct policy_set *ps = &ctx->shm->zone_pair_values[pos];
	 *
	 * 3. Iterate rules in the policy set:
	 *    for (uint16_t i = 0; i < ps->num_rules; i++) {
	 *        uint32_t rule_idx = ps->policy_set_id * MAX_RULES_PER_POLICY + i;
	 *        struct policy_rule *rule = &ctx->shm->policy_rules[rule_idx];
	 *
	 *        if (!rule->active)
	 *            continue;
	 *
	 *        // Match source address (LPM lookup in address_book_v4/v6)
	 *        if (rule->src_addr_id != 0) {
	 *            uint32_t src_id = lpm_lookup_address(ctx, meta, 1);
	 *            if (src_id != rule->src_addr_id)
	 *                continue;
	 *        }
	 *
	 *        // Match destination address
	 *        if (rule->dst_addr_id != 0) {
	 *            uint32_t dst_id = lpm_lookup_address(ctx, meta, 0);
	 *            if (dst_id != rule->dst_addr_id)
	 *                continue;
	 *        }
	 *
	 *        // Match protocol
	 *        if (rule->protocol != 0 && rule->protocol != meta->protocol)
	 *            continue;
	 *
	 *        // Match destination port range
	 *        if (rule->dst_port_low != 0) {
	 *            uint16_t port = rte_be_to_cpu_16(meta->dst_port);
	 *            uint16_t lo = rte_be_to_cpu_16(rule->dst_port_low);
	 *            uint16_t hi = rte_be_to_cpu_16(rule->dst_port_high);
	 *            if (port < lo || port > hi)
	 *                continue;
	 *        }
	 *
	 *        // Match application
	 *        if (rule->app_id != 0) {
	 *            struct app_key ak = {
	 *                .protocol = meta->protocol,
	 *                .dst_port = meta->dst_port,
	 *            };
	 *            int apos = rte_hash_lookup(ctx->shm->applications, &ak);
	 *            if (apos < 0 || ctx->shm->app_values[apos].app_id != rule->app_id)
	 *                continue;
	 *        }
	 *
	 *        // Match found
	 *        meta->policy_id = rule->rule_id;
	 *
	 *        // Counter
	 *        if (rule->counter_id != 0)
	 *            ctr_policy_add(ctx, rule->counter_id, rte_pktmbuf_pkt_len(pkt));
	 *
	 *        // NAT rule association
	 *        if (rule->nat_rule_id != 0) {
	 *            // TODO: Look up SNAT/DNAT rules and set meta->nat_*
	 *        }
	 *
	 *        // Logging
	 *        if (rule->log) {
	 *            // TODO: Emit event to event_ring
	 *        }
	 *
	 *        return rule->action;
	 *    }
	 *
	 * 4. No rule matched -> use policy_set default action
	 *    return ps->default_action;
	 */

	(void)ctx;
	(void)meta;

	/* Default: deny (matches BPF behavior) */
	ctr_global_inc(ctx, GLOBAL_CTR_POLICY_DENY);
	return ACTION_DENY;
}
