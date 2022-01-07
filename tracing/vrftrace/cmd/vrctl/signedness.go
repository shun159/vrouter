package main

import "github.com/apache/thrift/lib/go/thrift"

var SIGNEDNESS = map[string]map[int16]bool{
	"sandesh_hdr": {
		1: false,
		2: false,
	},

	"vr_nexthop_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: true,
		11: true,
		12: false,
		13: false,
		14: false,
		15: false,
		16: true,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: true,
		30: false,
	},

	"vr_interface_req": {
		1:  false,
		2:  true,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
		34: false,
		35: false,
		36: false,
		37: false,
		38: false,
		39: true,
		40: true,
		41: true,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
		48: false,
		49: false,
		50: false,
		51: false,
		52: false,
		53: false,
		54: false,
		55: false,
		56: false,
		57: false,
		58: true,
		59: false,
		60: true,
		61: false,
		62: false,
		63: false,
		64: false,
		65: true,
		66: true,
		67: true,
		68: true,
		77: true,
		78: true,
		79: false,
		80: false,
		81: true,
		82: true,
		83: false,
		84: false,
		85: false,
		86: false,
		87: false,
		88: false,
		89: false,
		90: false,
		91: true,
		92: false,
		93: true,
	},

	"vr_vxlan_req": {
		1: false,
		2: false,
		3: false,
		4: false,
	},

	"vr_route_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
	},

	"vr_mpls_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
	},

	"vr_mirror_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
		8: false,
		9: false,
	},

	"vr_vrf_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
	},

	"vr_flow_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  true,
		9:  true,
		10: true,
		11: true,
		12: true,
		13: true,
		14: false,
		15: true,
		16: true,
		17: true,
		18: true,
		19: true,
		20: true,
		21: false,
		22: true,
		23: true,
		24: true,
		25: true,
		26: true,
		27: false,
		28: true,
		29: true,
		30: true,
		31: true,
		32: true,
		33: true,
		34: true,
		35: true,
		36: false,
		37: false,
		38: false,
		39: false,
	},

	"vr_vrf_assign_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
	},

	"vr_vrf_stats_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
	},

	"vr_response": {
		1: false,
		2: false,
	},

	"vrouter_ops": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: true,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: true,
		31: true,
		32: true,
		33: true,
		34: false,
		35: false,
		36: false,
		37: false,
		38: true,
		39: false,
		40: false,
		41: false,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
	},

	"vr_mem_stats_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
		34: false,
		35: false,
		36: false,
		37: false,
		38: false,
		39: false,
		40: false,
		41: false,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
		48: false,
		49: false,
		50: false,
		51: false,
		52: false,
		53: false,
		54: false,
		55: false,
		56: false,
		57: false,
		58: false,
		59: false,
		60: false,
		61: false,
		62: false,
		63: false,
		64: false,
		65: false,
		66: false,
		67: false,
		68: false,
		69: false,
		70: false,
		71: false,
		72: false,
	},

	"vr_info_req": {
		1: false,
		2: false,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
		8: false,
		9: false,
	},

	"vr_pkt_drop_log_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
	},

	"vr_drop_stats_req": {
		1:  false,
		2:  false,
		3:  false,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
		11: false,
		12: false,
		13: false,
		14: false,
		15: false,
		16: false,
		17: false,
		18: false,
		19: false,
		20: false,
		21: false,
		22: false,
		23: false,
		24: false,
		25: false,
		26: false,
		27: false,
		28: false,
		29: false,
		30: false,
		31: false,
		32: false,
		33: false,
		34: false,
		35: false,
		36: false,
		37: false,
		38: false,
		39: false,
		40: false,
		41: false,
		42: false,
		43: false,
		44: false,
		45: false,
		46: false,
		47: false,
		48: false,
		49: false,
		50: false,
		51: false,
		52: false,
		53: false,
		54: false,
		55: false,
		56: false,
		57: false,
		58: false,
	},

	"vr_qos_map_req": {
		1:  false,
		2:  true,
		3:  true,
		4:  false,
		5:  false,
		6:  false,
		7:  false,
		8:  false,
		9:  false,
		10: false,
	},

	"vr_fc_map_req": {
		1: false,
		2: true,
		3: false,
		4: false,
		5: false,
		6: false,
		7: false,
		8: false,
	},

	"vr_flow_response": {
		1: false,
		2: true,
		3: true,
		4: true,
		5: true,
		6: true,
		7: true,
		8: false,
	},

	"vr_flow_table_data": {
		1:  false,
		2:  true,
		3:  true,
		4:  true,
		5:  false,
		6:  true,
		7:  true,
		8:  true,
		9:  true,
		10: true,
		11: true,
		12: true,
		13: true,
		14: true,
		15: true,
		16: true,
		17: true,
	},

	"vr_bridge_table_data": {
		1: false,
		2: true,
		3: true,
		4: true,
		5: false,
	},

	"vr_hugepage_config": {
		1: false,
		2: true,
		3: true,
		4: true,
		5: true,
		6: false,
		7: true,
	},
}

const (
	STOP     = 0
	VOID     = 1
	BOOL     = 2
	BYTE     = 3
	I08      = 3
	DOUBLE   = 4
	I16      = 6
	I32      = 8
	T_U64    = 9
	I64      = 10
	STRING   = 11
	UTF7     = 11
	STRUCT   = 12
	MAP      = 13
	SET      = 14
	LIST     = 15
	UTF8     = 16
	UTF16    = 17
	T_U16    = 19
	T_U32    = 20
	T_XML    = 21
	T_IPV4   = 22
	T_UUID   = 23
	T_IPADDR = 24
)

func signedness(st_name string) (map[int16]bool, bool) {
	if v, ok := SIGNEDNESS[st_name]; ok {
		return v, ok
	} else {
		return make(map[int16]bool), false
	}
}

func translate_ttype_to_stype(ttype thrift.TType, unsigned bool) thrift.TType {
	if ttype == I16 && unsigned {
		return T_U16
	} else if ttype == I32 && unsigned {
		return T_U32
	} else if ttype == I64 && unsigned {
		return T_U64
	} else {
		return ttype
	}
}

func translate_stype_to_ttype(ttype thrift.TType) thrift.TType {
	switch ttype {
	case T_U16:
		return I16
	case T_U32:
		return I32
	case T_U64:
		return I64
	default:
		return ttype
	}
}