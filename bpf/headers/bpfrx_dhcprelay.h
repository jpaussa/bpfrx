// SPDX-License-Identifier: GPL-2.0
#ifndef __BPFRX_DHCPRELAY_H__
#define __BPFRX_DHCPRELAY_H__

#include "bpfrx_common.h"

/* ============================================================
 * DHCP Relay Configuration
 * ============================================================ */

/* Composite key for dhcp_relay_map: {ifindex, vlan_id, family} -> dhcp_relay_config */
struct dhcp_relay_key {
	__u32 ifindex;
	__u16 vlan_id;
	__u8  family;  /* AF_INET or AF_INET6 */
	__u8  pad;
};

/* Value: DHCP relay configuration for an interface */
struct dhcp_relay_config {
	__u8  enabled;
	__u8  pad[7];  /* alignment */
};

#endif /* __BPFRX_DHCPRELAY_H__ */
