/* SPDX-License-Identifier: GPL-2.0-or-later
 * zone.c — Zone lookup (replaces xdp_zone).
 *
 * Looks up the security zone for the ingress interface + VLAN,
 * applying host-inbound-traffic checks for local-destined packets.
 */

#include <rte_mbuf.h>
#include <rte_hash.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * zone_lookup — Determine the ingress security zone.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata (ingress_ifindex, ingress_vlan_id set)
 * @ctx:  Pipeline context (shared memory with zone tables)
 *
 * Sets meta->ingress_zone and meta->routing_table based on the
 * iface_zone_map lookup using {ifindex, vlan_id} as key.
 *
 * Also checks host-inbound-traffic flags if the packet is destined
 * to the firewall itself (local delivery).
 */
void
zone_lookup(struct rte_mbuf *pkt, struct pkt_meta *meta,
            struct pipeline_ctx *ctx)
{
	(void)pkt;

	/* TODO: Implement zone lookup:
	 *
	 * 1. Build iface_zone_key from meta->ingress_ifindex + ingress_vlan_id
	 *
	 * 2. Look up in iface_zone_map hash table:
	 *    struct iface_zone_key zk = {
	 *        .ifindex = meta->ingress_ifindex,
	 *        .vlan_id = meta->ingress_vlan_id,
	 *    };
	 *    int pos = rte_hash_lookup(ctx->shm->iface_zone_map, &zk);
	 *    if (pos >= 0) {
	 *        struct iface_zone_value *zv = &ctx->shm->iface_zone_values[pos];
	 *        meta->ingress_zone = zv->zone_id;
	 *        meta->routing_table = zv->routing_table;
	 *    }
	 *
	 * 3. Load zone_config for ingress_zone:
	 *    struct zone_config *zc = &ctx->shm->zone_configs[meta->ingress_zone];
	 *
	 * 4. Check host-inbound-traffic if packet is destined to firewall:
	 *    - Compare dst_ip against configured interface addresses
	 *    - If local-destined, check zc->host_inbound_flags against protocol/port
	 *    - Drop if service not allowed
	 *
	 * 5. Pre-routing FIB lookup (optional, for egress zone determination):
	 *    - Use routing_table to select VRF
	 *    - Look up dst_ip in FIB for egress interface
	 *    - Map egress interface to egress_zone
	 */

	/* Default: zone 0, main routing table */
	meta->ingress_zone = 0;
	meta->routing_table = 0;
}
