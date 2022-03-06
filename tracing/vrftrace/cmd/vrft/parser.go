package main

import (
	"context"
	"encoding/binary"
	"net"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/shun159/vrftrace/vr"
	"golang.org/x/sys/unix"
)

type PerfEvent struct {
	Tstamp      uint64
	Faddr       uint64
	ProcessorId uint32
	IsReturn    uint8
	Idx         uint64
	Fname       string
	Sname       string
}

type VrPacket struct {
	EthDstAddr net.HardwareAddr
	EthSrcAddr net.HardwareAddr
	EthType    uint16
	IPVersion  uint8
	IPProtocol uint8
	IPSrcAddr  net.IP
	IPDstAddr  net.IP
}

func (pkt *VrPacket) Read(ctx context.Context, p thrift.TProtocol) error {
	return nil
}

func (pkt *VrPacket) Write(ctx context.Context, p thrift.TProtocol) error {
	return nil
}

func parsePerfEvent(b []byte, symdb SymsDB) PerfEvent {
	perf := PerfEvent{}
	perf.Tstamp = binary.LittleEndian.Uint64(b[0:8])
	perf.Faddr = binary.LittleEndian.Uint64(b[8:16])
	perf.ProcessorId = binary.LittleEndian.Uint32(b[16:20])
	perf.IsReturn = b[20:21][0]
	_ = b[21:24] // _pad[3]
	perf.Idx = binary.LittleEndian.Uint64(b[24:32])
	if s, ok := symdb.Address[perf.Faddr]; ok {
		perf.Fname = s
		if syminfo, ok := symdb.SymInfo[perf.Fname]; ok {
			perf.Sname = syminfo.Sname
		}
	}
	return perf
}

func parseSreq(perf PerfEvent, data []byte) vr.Sandesh {
	switch perf.Sname {
	case "vr_interface_req":
		req := parseVifr(data)
		return req
	case "vr_route_req":
		req := parseRtr(data)
		return req
	case "vr_nexthop_req":
		req := parseNhr(data)
		return req
	case "vr_vrf_assign_req":
		req := parseVar(data)
		return req
	case "vr_mpls_req":
		req := parseMr(data)
		return req
	case "vr_vrf_stats_req":
		req := parseVsr(data)
		return req
	case "vr_mirror_req":
		req := parseMirr(data)
		return req
	case "vr_flow_req":
		req := parseFr(data)
		return req
	case "vr_response":
		req := parseResp(data)
		return req
	case "vr_flow_table_data":
		req := parseFtable(data)
		return req
	case "vr_vrf_req":
		req := parseVrf(data)
		return req
	case "vr_vxlan_req":
		req := parseVxlan(data)
		return req
	case "vr_fc_map_req":
		req := parseFmr(data)
		return req
	case "vr_qos_map_req":
		req := parseFmr(data)
		return req
	case "vr_drop_stats_req":
		req := parseVds(data)
		return req
	case "vr_bridge_table_data":
		req := parseBtable(data)
		return req
	case "vr_packet":
		req := parseVrPacket(data)
		return req
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
	req.VifrIP = int32(binary.BigEndian.Uint32(b[44:48]))
	req.VifrIp6U = int64(binary.BigEndian.Uint64(b[48:56]))
	req.VifrIp6L = int64(binary.BigEndian.Uint64(b[56:64]))
	// b[64:66] // pad
	req.VifrVlanID = int16(binary.LittleEndian.Uint16(b[66:68]))
	req.VifrNhID = int32(binary.LittleEndian.Uint32(b[68:72]))
	// b[72:79] // pad
	req.VifrTransport = int8(b[79:80][0])
	req.VifrName = string(b[80:96])

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
	// _ = int16(binary.LittleEndian.Uint16(b[104:110])) // pad2
	req.VsrMarker = int16(binary.LittleEndian.Uint16(b[110:112]))
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

func parseMirr(b []byte) *vr.VrMirrorReq {
	req := vr.NewVrMirrorReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.MirrIndex = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.MirrRid = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.MirrNhid = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.MirrUsers = int32(binary.LittleEndian.Uint32(b[12:16]))
	req.MirrFlags = int32(binary.LittleEndian.Uint32(b[16:20]))
	req.MirrMarker = int32(binary.LittleEndian.Uint32(b[20:24]))
	req.MirrVni = int32(binary.LittleEndian.Uint32(b[24:28]))
	// int32(binary.LittleEndian.Uint32(b[28:30])) // pad
	req.MirrVlan = int16(binary.LittleEndian.Uint16(b[30:32]))

	return req
}

func parseFr(b []byte) *vr.VrFlowReq {
	req := vr.NewVrFlowReq()
	req.FrOp = vr.FlowOp(b[0:4][0])
	// b[4:6] // pad
	req.FrRid = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.FrIndex = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.FrAction = int16(binary.LittleEndian.Uint16(b[12:14]))
	req.FrFlags = int16(binary.LittleEndian.Uint16(b[14:16]))
	req.FrRindex = int32(binary.LittleEndian.Uint32(b[16:20]))
	req.FrFamily = int32(binary.LittleEndian.Uint32(b[20:24]))
	req.FrFlowSipU = int64(binary.LittleEndian.Uint64(b[24:32]))
	req.FrFlowSipL = int64(binary.LittleEndian.Uint64(b[32:40]))
	req.FrFlowDipU = int64(binary.LittleEndian.Uint64(b[40:48]))
	req.FrFlowDipL = int64(binary.LittleEndian.Uint64(b[48:56]))
	req.FrFlowSport = int16(binary.LittleEndian.Uint16(b[56:58]))
	req.FrFlowDport = int16(binary.LittleEndian.Uint16(b[58:60]))
	// b[60:63] // pad
	req.FrFlowProto = int8(b[63:64][0])
	req.FrFlowVrf = int16(binary.LittleEndian.Uint16(b[64:66]))
	req.FrFlowDvrf = int16(binary.LittleEndian.Uint16(b[66:68]))
	req.FrMirID = int16(binary.LittleEndian.Uint16(b[68:70]))
	req.FrSecMirID = int16(binary.LittleEndian.Uint16(b[70:72]))
	req.FrMirSip = int32(binary.LittleEndian.Uint32(b[72:76]))
	req.FrMirSport = int16(binary.LittleEndian.Uint16(b[76:78]))
	req.FrMirVrf = int16(binary.LittleEndian.Uint16(b[78:80]))
	req.FrEcmpNhIndex = int32(binary.LittleEndian.Uint32(b[80:84]))
	req.FrSrcNhIndex = int32(binary.LittleEndian.Uint32(b[84:88]))
	req.FrFlowNhID = int32(binary.LittleEndian.Uint32(b[88:92]))
	req.FrDropReason = int16(binary.LittleEndian.Uint16(b[92:94]))
	// b[94:95] // pad
	req.FrGenID = int8(b[95:96][0])
	req.FrRflowSipL = int64(binary.LittleEndian.Uint64(b[96:104]))
	req.FrRflowSipU = int64(binary.LittleEndian.Uint64(b[104:112]))
	req.FrRflowDipL = int64(binary.LittleEndian.Uint64(b[112:120]))
	req.FrRflowDipU = int64(binary.LittleEndian.Uint64(b[120:128]))
	req.FrRflowNhID = int32(binary.LittleEndian.Uint32(b[128:132]))
	req.FrRflowSport = int16(binary.LittleEndian.Uint16(b[132:134]))
	req.FrRflowDport = int16(binary.LittleEndian.Uint16(b[134:136]))
	req.FrQosID = int16(binary.LittleEndian.Uint16(b[136:138]))
	// b[138:143] //pad
	req.FrTTL = int8(b[143:144][0])
	req.FrExtflags = int16(binary.LittleEndian.Uint16(b[144:146]))
	req.FrFlags = int16(binary.LittleEndian.Uint16(b[146:148]))
	req.FrUnderlayEcmpIndex = int8(b[148:149][0])
	// b[149:152] // pad

	return req
}

func parseResp(b []byte) *vr.VrResponse {
	req := vr.NewVrResponse()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.RespCode = int32(binary.LittleEndian.Uint32(b[4:8]))

	return req
}

func parseFtable(b []byte) *vr.VrFlowTableData {
	req := vr.NewVrFlowTableData()
	req.FtableOp = vr.FlowOp(b[0:4][0])
	req.FtableRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.FtableDev = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.FtableUsedEntries = int64(binary.LittleEndian.Uint64(b[8:16]))
	req.FtableProcessed = int64(binary.LittleEndian.Uint64(b[16:24]))
	req.FtableDeleted = int64(binary.LittleEndian.Uint64(b[24:32]))
	req.FtableAdded = int64(binary.LittleEndian.Uint64(b[32:40]))
	req.FtableCreated = int64(binary.LittleEndian.Uint64(b[40:48]))
	req.FtableChanged = int64(binary.LittleEndian.Uint64(b[48:56]))
	req.FtableSize = int32(binary.LittleEndian.Uint32(b[56:60]))
	req.FtableHoldEntries = int32(binary.LittleEndian.Uint32(b[60:64]))
	req.FtableCpus = int32(binary.LittleEndian.Uint32(b[64:68]))
	req.FtableOflowEntries = int32(binary.LittleEndian.Uint32(b[68:72]))
	req.FtableBurstFreeTokens = int32(binary.LittleEndian.Uint32(b[72:76]))
	req.FtableHoldEntries = int32(binary.LittleEndian.Uint32(b[76:80]))

	return req
}

func parseVrf(b []byte) *vr.VrVrfReq {
	req := vr.NewVrVrfReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	// b[4:6] // pad
	req.VrfRid = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.VrfIdx = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.VrfFlags = int32(binary.LittleEndian.Uint32(b[12:16]))
	req.VrfHbflVifIdx = int32(binary.LittleEndian.Uint32(b[16:20]))
	req.VrfHbfrVifIdx = int32(binary.LittleEndian.Uint32(b[20:24]))
	req.VrfMarker = int32(binary.LittleEndian.Uint32(b[24:28]))

	return req
}

func parseVxlan(b []byte) *vr.VrVxlanReq {
	req := vr.NewVrVxlanReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	// b[4:6] // pad
	req.VxlanrRid = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.VxlanrVnid = int32(binary.LittleEndian.Uint32(b[8:12]))
	req.VxlanrNhid = int32(binary.LittleEndian.Uint32(b[12:16]))

	return req
}

func parseFmr(b []byte) *vr.VrFcMapReq {
	req := vr.NewVrFcMapReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.FmrRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.FmrMarker = int16(binary.LittleEndian.Uint16(b[6:8]))

	return req
}

func parseQmr(b []byte) *vr.VrQosMapReq {
	req := vr.NewVrQosMapReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.QmrRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.QmrID = int16(binary.LittleEndian.Uint16(b[6:8]))
	// b[8:14] // pad
	req.QmrMarker = int16(binary.LittleEndian.Uint16(b[14:16]))

	return req
}

func parseVds(b []byte) *vr.VrDropStatsReq {
	req := vr.NewVrDropStatsReq()
	req.HOp = vr.SandeshOp(b[0:4][0])
	req.VdsRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.VdsCore = int16(binary.LittleEndian.Uint16(b[6:8]))
	req.VdsDiscard = int64(binary.LittleEndian.Uint64(b[8:16]))
	// b[16:23] // pad
	req.VdsPcpuStatsFailureStatus = int8(b[23:24][0])
	req.VdsPull = int64(binary.LittleEndian.Uint64(b[24:32]))
	req.VdsInvalidIf = int64(binary.LittleEndian.Uint64(b[32:40]))
	req.VdsInvalidArp = int64(binary.LittleEndian.Uint64(b[40:48]))
	req.VdsTrapNoIf = int64(binary.LittleEndian.Uint64(b[48:56]))
	req.VdsNowhereToGo = int64(binary.LittleEndian.Uint64(b[56:64]))
	req.VdsFlowQueueLimitExceeded = int64(binary.LittleEndian.Uint64(b[64:72]))
	req.VdsFlowNoMemory = int64(binary.LittleEndian.Uint64(b[72:80]))
	req.VdsFlowInvalidProtocol = int64(binary.LittleEndian.Uint64(b[80:88]))
	req.VdsFlowNatNoRflow = int64(binary.LittleEndian.Uint64(b[88:96]))
	req.VdsFlowActionDrop = int64(binary.LittleEndian.Uint64(b[96:104]))
	req.VdsFlowActionInvalid = int64(binary.LittleEndian.Uint64(b[104:112]))
	req.VdsFlowUnusable = int64(binary.LittleEndian.Uint64(b[112:120]))
	req.VdsFlowTableFull = int64(binary.LittleEndian.Uint64(b[120:128]))
	req.VdsInterfaceTxDiscard = int64(binary.LittleEndian.Uint64(b[128:136]))
	req.VdsInterfaceDrop = int64(binary.LittleEndian.Uint64(b[136:144]))
	req.VdsDuplicated = int64(binary.LittleEndian.Uint64(b[144:152]))
	req.VdsPush = int64(binary.LittleEndian.Uint64(b[152:160]))
	req.VdsTTLExceeded = int64(binary.LittleEndian.Uint64(b[160:168]))
	req.VdsInvalidNh = int64(binary.LittleEndian.Uint64(b[168:176]))
	req.VdsInvalidLabel = int64(binary.LittleEndian.Uint64(b[176:184]))
	req.VdsInvalidProtocol = int64(binary.LittleEndian.Uint64(b[184:192]))
	req.VdsInterfaceRxDiscard = int64(binary.LittleEndian.Uint64(b[192:200]))
	req.VdsInvalidMcastSource = int64(binary.LittleEndian.Uint64(b[200:208]))
	req.VdsHeadAllocFail = int64(binary.LittleEndian.Uint64(b[208:216]))
	req.VdsPcowFail = int64(binary.LittleEndian.Uint64(b[216:224]))
	req.VdsMcastDfBit = int64(binary.LittleEndian.Uint64(b[224:232]))
	req.VdsMcastCloneFail = int64(binary.LittleEndian.Uint64(b[232:240]))
	req.VdsNoMemory = int64(binary.LittleEndian.Uint64(b[240:248]))
	req.VdsRewriteFail = int64(binary.LittleEndian.Uint64(b[248:256]))
	req.VdsMisc = int64(binary.LittleEndian.Uint64(b[256:264]))
	req.VdsInvalidPacket = int64(binary.LittleEndian.Uint64(b[264:272]))
	req.VdsCksumErr = int64(binary.LittleEndian.Uint64(b[272:280]))
	req.VdsNoFmd = int64(binary.LittleEndian.Uint64(b[280:288]))
	req.VdsClonedOriginal = int64(binary.LittleEndian.Uint64(b[288:296]))
	req.VdsInvalidVnid = int64(binary.LittleEndian.Uint64(b[296:304]))
	req.VdsFragErr = int64(binary.LittleEndian.Uint64(b[304:312]))
	req.VdsInvalidSource = int64(binary.LittleEndian.Uint64(b[312:320]))
	req.VdsL2NoRoute = int64(binary.LittleEndian.Uint64(b[320:328]))
	req.VdsFragmentQueueFail = int64(binary.LittleEndian.Uint64(b[328:336]))
	req.VdsVlanFwdTx = int64(binary.LittleEndian.Uint64(b[336:344]))
	req.VdsVlanFwdEnq = int64(binary.LittleEndian.Uint64(b[344:352]))
	req.VdsDropNewFlow = int64(binary.LittleEndian.Uint64(b[352:360]))
	req.VdsFlowEvict = int64(binary.LittleEndian.Uint64(b[360:368]))
	req.VdsTrapOriginal = int64(binary.LittleEndian.Uint64(b[368:376]))
	req.VdsLeafToLeaf = int64(binary.LittleEndian.Uint64(b[376:384]))
	req.VdsBmacIsidMismatch = int64(binary.LittleEndian.Uint64(b[384:392]))
	req.VdsPktLoop = int64(binary.LittleEndian.Uint64(b[392:400]))
	req.VdsNoCryptPath = int64(binary.LittleEndian.Uint64(b[400:408]))
	req.VdsInvalidHbsPkt = int64(binary.LittleEndian.Uint64(b[408:416]))
	req.VdsNoFragEntry = int64(binary.LittleEndian.Uint64(b[416:424]))
	req.VdsIcmpError = int64(binary.LittleEndian.Uint64(b[424:432]))

	return req
}

func parseBtable(b []byte) *vr.VrBridgeTableData {
	req := vr.NewVrBridgeTableData()
	req.BtableOp = vr.SandeshOp(b[0:4][0])
	req.BtableRid = int16(binary.LittleEndian.Uint16(b[4:6]))
	req.BtableDev = int16(binary.LittleEndian.Uint16(b[6:8]))
	// b[8:12] // pad
	req.BtableSize = int32(binary.LittleEndian.Uint32(b[12:16]))

	return req
}

func parseVrPacket(b []byte) *VrPacket {
	req := &VrPacket{}
	req.EthDstAddr = b[0:6]
	req.EthSrcAddr = b[6:12]
	req.EthType = binary.BigEndian.Uint16(b[12:14])
	req.IPVersion = b[14:15][0]
	req.IPProtocol = b[15:16][0]

	if req.EthType == unix.ETH_P_IP {
		req.IPSrcAddr = net.IP(b[16:20])
		req.IPDstAddr = net.IP(b[144:148])
	} else if req.EthType == unix.ETH_P_IPV6 {
		req.IPSrcAddr = net.IP(b[16:144])
		req.IPDstAddr = net.IP(b[144:272])
	}

	return req
}
