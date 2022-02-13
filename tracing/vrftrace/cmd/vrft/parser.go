package main

import "C"
import (
	"encoding/binary"

	"github.com/shun159/vrftrace/vr"
)

func parseSreq(perf PerfEvent, data []byte) vr.Sandesh {
	switch perf.Sname {
	case "vr_interface_req":
		vifr := parseVifr(data)
		return vifr
	case "vr_route_req":
		rtr := parseRtr(data)
		return rtr
	case "vr_nexthop_req":
		nhr := parseNhr(data)
		return nhr
	case "vr_vrf_assign_req":
		nhr := parseVar(data)
		return nhr
	case "vr_mpls_req":
		nhr := parseMr(data)
		return nhr
	case "vr_vrf_stats_req":
		nhr := parseVsr(data)
		return nhr
	default:
		return nil
	}
}

func parseVifr(b []byte) *vr.VrInterfaceReq {
	req := vr.NewVrInterfaceReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.VifrCore = int32(binary.LittleEndian.Uint32(b[4:8]))
	req.VifrType = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.VifrFlags = int32(binary.LittleEndian.Uint32(b[12:16]))
	req.VifrVrf = int32(binary.LittleEndian.Uint32(b[16:20]))
	req.VifrIdx = int32(binary.LittleEndian.Uint32(b[20:24]))
	req.VifrRid = int32(binary.LittleEndian.Uint32(b[24:28]))
	req.VifrOsIdx = int32(binary.LittleEndian.Uint32(b[28:32]))
	req.VifrMtu = int32(binary.LittleEndian.Uint32(b[32:36]))
	req.VifrRefCnt = int32(binary.LittleEndian.Uint32(b[36:40]))
	req.VifrMarker = int32(binary.LittleEndian.Uint32(b[40:44]))
	req.VifrIP = int32(binary.BigEndian.Uint32(b[44:52]))
	req.VifrIp6U = int64(binary.BigEndian.Uint64(b[52:60]))
	req.VifrIp6L = int64(binary.BigEndian.Uint64(b[60:68]))
	req.VifrVlanID = int16(binary.LittleEndian.Uint16(b[68:70]))
	req.VifrNhID = int32(binary.LittleEndian.Uint32(b[70:74]))
	req.VifrTransport = int8(b[74:75][0])

	return req
}

func parseRtr(b []byte) *vr.VrRouteReq {
	req := vr.NewVrRouteReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.RtrVrfID = int32(binary.LittleEndian.Uint32(b[4:8]))
	req.RtrFamily = int32(binary.LittleEndian.Uint32(b[8:12]))
	// _ = int16(binary.LittleEndian.Uint16(b[12:14])) // pad
	req.RtrRid = int16(binary.LittleEndian.Uint16(b[14:16]))
	req.RtrNhID = int32(binary.LittleEndian.Uint32(b[16:20]))
	req.RtrIndex = int32(binary.LittleEndian.Uint32(b[20:24]))

	return req
}

func parseNhr(b []byte) *vr.VrNexthopReq {
	req := vr.NewVrNexthopReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	//_ = int16(binary.LittleEndian.Uint16(b[4:6])) // pad
	req.NhrType = int8(b[6:7][0])
	req.NhrFamily = int8(b[7:8][0])
	req.NhrID = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.NhrRid = int32(binary.LittleEndian.Uint32(b[12:16]))
	req.NhrFlags = int32(binary.LittleEndian.Uint32(b[16:20]))

	return req
}

func parseVar(b []byte) *vr.VrVrfAssignReq {
	req := vr.NewVrVrfAssignReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.VarRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.VarVifIndex = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.VarVifVrf = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.VarVlanID = int16(binary.LittleEndian.Uint16(b[12:14]))
	req.VarMarker = int16(binary.LittleEndian.Uint16(b[14:16]))
	req.VarNhID = int32(binary.LittleEndian.Uint32(b[16:20]))

	return req
}

func parseMr(b []byte) *vr.VrMplsReq {
	req := vr.NewVrMplsReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.MrLabel = int32(binary.LittleEndian.Uint32(b[4:8]))
	req.MrRid = int16(binary.LittleEndian.Uint16(b[8:10]))
	// _ = int16(binary.LittleEndian.Uint16(b[10:12])) // pad
	req.MrNhid = int32(binary.LittleEndian.Uint32(b[12:16]))
	req.MrMarker = int32(binary.LittleEndian.Uint32(b[16:20]))

	return req
}

func parseVsr(b []byte) *vr.VrVrfStatsReq {
	req := vr.NewVrVrfStatsReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.VsrRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.VsrFamily = int16(binary.LittleEndian.Uint16(b[6:8]))
	//_ = int16(binary.LittleEndian.Uint16(b[8:10])) // pad
	req.VsrType = int16(binary.LittleEndian.Uint16(b[10:12]))
	req.VsrVrf = int32(binary.LittleEndian.Uint32(b[12:16]))
	req.VsrDiscards = int64(binary.LittleEndian.Uint64(b[16:24]))
	req.VsrResolves = int64(binary.LittleEndian.Uint64(b[24:32]))
	req.VsrReceives = int64(binary.LittleEndian.Uint64(b[32:40]))
	req.VsrEcmpComposites = int64(binary.LittleEndian.Uint64(b[40:48]))
	req.VsrL2McastComposites = int64(binary.LittleEndian.Uint64(b[48:56]))
	req.VsrFabricComposites = int64(binary.LittleEndian.Uint64(b[56:64]))
	req.VsrUDPTunnels = int64(binary.LittleEndian.Uint64(b[64:72]))
	req.VsrUDPMplsTunnels = int64(binary.LittleEndian.Uint64(b[72:80]))
	req.VsrGreMplsTunnels = int64(binary.LittleEndian.Uint64(b[80:88]))
	req.VsrL2Encaps = int64(binary.LittleEndian.Uint64(b[88:96]))
	req.VsrEncaps = int64(binary.LittleEndian.Uint64(b[96:104]))
	// _ = int16(binary.LittleEndian.Uint16(b[112:118])) // pad2
	req.VsrMarker = int16(binary.LittleEndian.Uint16(b[104:112]))
	req.VsrGros = int64(binary.LittleEndian.Uint64(b[112:120]))
	req.VsrDiags = int64(binary.LittleEndian.Uint64(b[120:128]))
	req.VsrEncapComposites = int64(binary.LittleEndian.Uint64(b[128:136]))
	req.VsrEvpnComposites = int64(binary.LittleEndian.Uint64(b[136:144]))
	req.VsrVrfTranslates = int64(binary.LittleEndian.Uint64(b[144:152]))
	req.VsrVxlanTunnels = int64(binary.LittleEndian.Uint64(b[152:160]))
	req.VsrArpVirtualProxy = int64(binary.LittleEndian.Uint64(b[160:168]))
	req.VsrArpVirtualStitch = int64(binary.LittleEndian.Uint64(b[168:176]))
	req.VsrArpVirtualFlood = int64(binary.LittleEndian.Uint64(b[176:184]))
	req.VsrArpPhysicalStitch = int64(binary.LittleEndian.Uint64(b[184:192]))
	req.VsrArpTorProxy = int64(binary.LittleEndian.Uint64(b[192:200]))
	req.VsrArpPhysicalFlood = int64(binary.LittleEndian.Uint64(b[200:208]))
	req.VsrL2Receives = int64(binary.LittleEndian.Uint64(b[208:216]))
	req.VsrUucFloods = int64(binary.LittleEndian.Uint64(b[216:224]))
	req.VsrPbbTunnels = int64(binary.LittleEndian.Uint64(b[224:232]))
	req.VsrUDPMplsOverMplsTunnels = int64(binary.LittleEndian.Uint64(b[232:240]))

	return req
}
