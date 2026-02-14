/* SPDX-License-Identifier: GPL-2.0-or-later
 * screen.c — IDS/Screen checks (replaces xdp_screen).
 *
 * Implements stateless and rate-based DoS protection checks:
 * land attack, syn-flood, ping-of-death, teardrop, ICMP fragment,
 * large ICMP, tcp-no-flag, syn-frag, ip-sweep, port-scan, udp-flood.
 */

#include <rte_mbuf.h>

#include "shared_mem.h"
#include "tables.h"
#include "counters.h"

/**
 * screen_check — Run IDS/screen checks against the packet.
 *
 * @pkt:  Packet mbuf
 * @meta: Parsed packet metadata
 * @ctx:  Pipeline context (screen configs, flood state, counters)
 *
 * Returns 0 if packet passes all checks, -1 if it should be dropped.
 *
 * The screen profile is looked up by the zone's screen_profile_id
 * (set after zone_lookup). For ingress screening, we use the
 * ingress_zone's screen profile.
 */
int
screen_check(struct rte_mbuf *pkt, struct pkt_meta *meta,
             struct pipeline_ctx *ctx)
{
	/* TODO: Look up screen profile for ingress zone.
	 *
	 * struct screen_config *sc = &ctx->shm->screen_configs[screen_id];
	 * if (!sc || sc->flags == 0)
	 *     return 0;  // No screen profile or empty config
	 */

	(void)pkt;
	(void)meta;
	(void)ctx;

	/* TODO: Implement the following checks (matching bpf/xdp/xdp_screen.c):
	 *
	 * 1. Land attack (SCREEN_LAND_ATTACK):
	 *    - src_ip == dst_ip && src_port == dst_port
	 *    - Drop and increment GLOBAL_CTR_SCREEN_LAND_ATTACK
	 *
	 * 2. TCP SYN+FIN (SCREEN_TCP_SYN_FIN):
	 *    - TCP flags have both SYN and FIN set
	 *    - Drop and increment GLOBAL_CTR_SCREEN_TCP_SYN_FIN
	 *
	 * 3. TCP no flag (SCREEN_TCP_NO_FLAG):
	 *    - TCP flags == 0 (null scan)
	 *    - Drop and increment GLOBAL_CTR_SCREEN_TCP_NO_FLAG
	 *
	 * 4. TCP FIN no ACK (SCREEN_TCP_FIN_NO_ACK):
	 *    - TCP FIN set but ACK not set
	 *    - Drop and increment GLOBAL_CTR_SCREEN_TCP_FIN_NO_ACK
	 *
	 * 5. WinNuke (SCREEN_WINNUKE):
	 *    - TCP URG flag to port 139
	 *    - Drop and increment GLOBAL_CTR_SCREEN_WINNUKE
	 *
	 * 6. Ping of death (SCREEN_PING_OF_DEATH):
	 *    - ICMP packet with total length > 65535
	 *    - Drop and increment GLOBAL_CTR_SCREEN_PING_DEATH
	 *
	 * 7. Teardrop (SCREEN_TEAR_DROP):
	 *    - Overlapping IP fragments
	 *    - Drop and increment GLOBAL_CTR_SCREEN_TEAR_DROP
	 *
	 * 8. SYN fragment (SCREEN_SYN_FRAG):
	 *    - TCP SYN in a fragmented IP packet
	 *    - Drop and increment GLOBAL_CTR_SCREEN_SYN_FRAG
	 *
	 * 9. IP source route (SCREEN_IP_SOURCE_ROUTE):
	 *    - IP options include source routing
	 *    - Drop and increment GLOBAL_CTR_SCREEN_IP_SRC_ROUTE
	 *
	 * 10. SYN flood (SCREEN_SYN_FLOOD):
	 *     - Rate-limit TCP SYN packets per zone
	 *     - Uses per-lcore flood_state for rate tracking
	 *     - Drop and increment GLOBAL_CTR_SCREEN_SYN_FLOOD
	 *
	 * 11. ICMP flood (SCREEN_ICMP_FLOOD):
	 *     - Rate-limit ICMP echo requests per zone
	 *     - Drop and increment GLOBAL_CTR_SCREEN_ICMP_FLOOD
	 *
	 * 12. UDP flood (SCREEN_UDP_FLOOD):
	 *     - Rate-limit UDP packets per zone
	 *     - Drop and increment GLOBAL_CTR_SCREEN_UDP_FLOOD
	 *
	 * 13. Port scan (SCREEN_PORT_SCAN):
	 *     - Track unique destination ports per source IP
	 *     - Drop and increment GLOBAL_CTR_SCREEN_PORT_SCAN
	 *
	 * 14. IP sweep (SCREEN_IP_SWEEP):
	 *     - Track unique destination IPs per source IP
	 *     - Drop and increment GLOBAL_CTR_SCREEN_IP_SWEEP
	 */

	return 0;  /* Pass by default */
}
