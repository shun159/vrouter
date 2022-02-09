// SPDX-License-Identifier: BSD-2-Clause

#include <stdint.h>
#include <linux/types.h>
#include <linux/if.h>

#include "vr_types.h"

/* sandesh vr_interface_req */
struct vifr {
  sandesh_op h_op;
  unsigned char vifr_name[IFNAMSIZ];
  int32_t vifr_type;
  int32_t vifr_flags;
  int32_t vifr_vrf;
  int32_t vifr_idx;
  int32_t vifr_rid;
  int32_t vifr_os_idx;
  int32_t vifr_mtu;
  int16_t vifr_vlan_id;
};