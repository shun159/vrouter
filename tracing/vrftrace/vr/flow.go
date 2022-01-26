package vr

import (
	"encoding/binary"
	"net"
	"reflect"
	"strconv"
	"syscall"
)

// Flow Base struct
type Flow struct {
	*VrFlowReq
}

// Flow spec
type flowSpec struct {
	rid             int16
	index           int32
	action          int16
	flags           int16
	rindex          int32
	family          int32
	srcIP           net.IP
	dstIP           net.IP
	srcPort         int16
	dstPort         int16
	proto           int8
	vrf             int16
	dstVrf          int16
	mirId           int16
	secMirId        int16
	mirSrcIP        net.IP
	mirSrcPort      int16
	pcapMetaData    []int8
	mirVrf          int16
	ecmpNhIndex     int32
	srcNhIndex      int32
	nhId            int32
	dropReason      int16
	genId           int8
	reverseSrcIP    net.IP
	reverseDstIP    net.IP
	reverseNhId     int32
	reverseSrcPort  int16
	reverseDstPort  int16
	qosId           int16
	ttl             int8
	extflags        int16
	flags1          int16
	underlayEcmpIdx int8
}

func NewFlow(flowspec *flowSpec) (*Flow, error) {
	flow := &Flow{}
	flow.VrFlowReq = NewVrFlowReq()
	flow.FrOp = FlowOp_FLOW_SET
	flow.FrRid = flowspec.rid
	flow.FrAction = flowspec.action
	flow.FrFlags = flowspec.flags
	flow.FrIndex = flowspec.index
	flow.FrRindex = flowspec.rindex
	flow.FrFamily = flowspec.family

	src_upper, src_lower := ipToULInt64(flow.FrFamily, flowspec.srcIP)
	flow.FrFlowSipU = src_upper
	flow.FrFlowSipL = src_lower

	dst_upper, dst_lower := ipToULInt64(flow.FrFamily, flowspec.dstIP)
	flow.FrFlowDipU = dst_upper
	flow.FrFlowDipL = dst_lower

	flow.FrFlowSport = flowspec.srcPort
	flow.FrFlowDport = flowspec.dstPort
	flow.FrFlowProto = flowspec.proto
	flow.FrFlowVrf = flowspec.vrf
	flow.FrFlowDvrf = flowspec.dstVrf
	flow.FrMirID = flowspec.mirId
	flow.FrSecMirID = flowspec.secMirId

	if len(flowspec.mirSrcIP) < 4 {
		flow.FrMirSip = 0
	} else {
		flow.FrMirSip = int32(binary.LittleEndian.Uint32(flowspec.mirSrcIP.To4()))
	}

	flow.FrMirSport = flowspec.mirSrcPort
	flow.FrPcapMetaData = flowspec.pcapMetaData
	flow.FrMirVrf = flowspec.mirVrf
	flow.FrEcmpNhIndex = flowspec.ecmpNhIndex
	flow.FrSrcNhIndex = flowspec.srcNhIndex
	flow.FrFlowNhID = flowspec.nhId
	flow.FrDropReason = flowspec.dropReason
	flow.FrGenID = flowspec.genId

	rsrc_upper, rsrc_lower := ipToULInt64(flow.FrFamily, flowspec.reverseSrcIP)
	flow.FrRflowSipU = rsrc_upper
	flow.FrRflowSipL = rsrc_lower

	rdst_upper, rdst_lower := ipToULInt64(flow.FrFamily, flowspec.reverseDstIP)
	flow.FrRflowDipU = rdst_upper
	flow.FrRflowDipL = rdst_lower

	flow.FrRflowNhID = flowspec.reverseNhId
	flow.FrRflowSport = flowspec.reverseSrcPort
	flow.FrRflowDport = flowspec.reverseDstPort
	flow.FrQosID = flowspec.qosId
	flow.FrTTL = flowspec.ttl
	flow.FrExtflags = flowspec.extflags
	flow.FrFlags1 = flowspec.flags1
	flow.FrUnderlayEcmpIndex = flowspec.underlayEcmpIdx

	return flow, nil
}

// InetFlow config
type InetFlowConfig struct {
	// Mandatory Parameters
	SrcIP    string `default:"0.0.0.0"`
	DstIP    string `default:"0.0.0.0"`
	SrcPort  uint16
	DstPort  uint16
	Protocol int8
	Action   int16 `default:"2"`
	// Optional Parameters
	Index          int32 `default:"-1"`
	Flags          int16 `default:"1"`
	Nexthop        int32
	ReverseNexthop int32 `default:"0"`
	Vrf            int16
}

// Create inetflow config with default values
func NewInetFlowConfig() InetFlowConfig {
	var f reflect.StructField
	conf := InetFlowConfig{}
	typ := reflect.TypeOf(VirtualVifConfig{})

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = int16(flags)

	f, _ = typ.FieldByName("Action")
	action, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Action = int16(action)

	f, _ = typ.FieldByName("SrcIP")
	srcIP := f.Tag.Get("default")
	conf.SrcIP = srcIP

	f, _ = typ.FieldByName("DstIP")
	dstIP := f.Tag.Get("default")
	conf.DstIP = dstIP

	f, _ = typ.FieldByName("Index")
	index, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Index = int32(index)

	f, _ = typ.FieldByName("ReverseNexthop")
	rflow_nh, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.ReverseNexthop = int32(rflow_nh)

	return conf
}

func NewInetFlow(conf InetFlowConfig) (*Flow, error) {
	flowspec := flowSpec{
		index:          conf.Index,
		action:         conf.Action,
		family:         syscall.AF_INET,
		srcIP:          net.ParseIP(conf.SrcIP),
		dstIP:          net.ParseIP(conf.DstIP),
		srcPort:        int16(conf.SrcPort),
		dstPort:        int16(conf.DstPort),
		proto:          conf.Protocol,
		nhId:           conf.Nexthop,
		vrf:            conf.Vrf,
		reverseNhId:    conf.ReverseNexthop,
		flags:          conf.Flags,
		reverseSrcIP:   net.ParseIP(conf.DstIP),
		reverseDstIP:   net.ParseIP(conf.SrcIP),
		reverseSrcPort: int16(conf.DstPort),
		reverseDstPort: int16(conf.SrcPort),
	}

	return NewFlow(&flowspec)
}

// Inet6Flow config
type Inet6FlowConfig struct {
	// Mandatory Parameters
	SrcIP    string `default:"::"`
	DstIP    string `default:"::"`
	SrcPort  int16
	DstPort  uint16
	Protocol int8
	// Optional Parameters
	Flags          int16 `default:"1"`
	Nexthop        int32
	ReverseNexthop int32
	Vrf            int16
}

// Create inetflow config with default values
func NewInet6FlowConfig() Inet6FlowConfig {
	var f reflect.StructField
	conf := Inet6FlowConfig{}
	typ := reflect.TypeOf(VirtualVifConfig{})

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = int16(flags)

	f, _ = typ.FieldByName("SrcIP")
	srcIP := f.Tag.Get("default")
	conf.SrcIP = srcIP

	f, _ = typ.FieldByName("DstIP")
	dstIP := f.Tag.Get("default")
	conf.DstIP = dstIP

	return conf
}

func NewInet6Flow(conf Inet6FlowConfig) (*Flow, error) {
	flowspec := flowSpec{
		family:         syscall.AF_INET6,
		srcIP:          net.ParseIP(conf.SrcIP),
		dstIP:          net.ParseIP(conf.DstIP),
		srcPort:        int16(conf.SrcPort),
		dstPort:        int16(conf.DstPort),
		proto:          conf.Protocol,
		nhId:           conf.Nexthop,
		vrf:            conf.Vrf,
		reverseNhId:    conf.ReverseNexthop,
		flags:          conf.Flags,
		reverseSrcIP:   net.ParseIP(conf.DstIP),
		reverseDstIP:   net.ParseIP(conf.SrcIP),
		reverseSrcPort: int16(conf.DstPort),
		reverseDstPort: int16(conf.SrcPort),
	}

	return NewFlow(&flowspec)
}

// NatFlow config
type NatFlowConfig struct {
	// Mandatory Parameters
	SrcIP          string `default:"0.0.0.0"`
	DstIP          string `default:"0.0.0.0"`
	SrcPort        uint16 `default:"0"`
	DstPort        uint16 `default:"0"`
	Protocol       int8
	Dvrf           int16
	ReverseSrcIP   string `default:"0.0.0.0"`
	ReverseDstIP   string `default:"0.0.0.0"`
	Flags          uint16 `default:"1"`
	Nexthop        int32
	SrcNexthop     int32
	QosId          int16
	Action         int16
	EcmpNexthop    int32
	Vrf            int16
	ReverseNexthop int32
	ReverseSrcPort uint16 `default:"0"`
}

// Create inetflow config with default values
func NewNatFlowConfig() NatFlowConfig {
	var f reflect.StructField
	conf := NatFlowConfig{}
	typ := reflect.TypeOf(VirtualVifConfig{})

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = uint16(flags)

	f, _ = typ.FieldByName("SrcIP")
	srcIP := f.Tag.Get("default")
	conf.SrcIP = srcIP

	f, _ = typ.FieldByName("DstIP")
	dstIP := f.Tag.Get("default")
	conf.DstIP = dstIP

	f, _ = typ.FieldByName("SrcPort")
	srcPort, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.SrcPort = uint16(srcPort)

	f, _ = typ.FieldByName("SrcPort")
	dstPort, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.DstPort = uint16(dstPort)

	f, _ = typ.FieldByName("ReverseSrcPort")
	rsrcPort, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.ReverseSrcPort = uint16(rsrcPort)

	f, _ = typ.FieldByName("ReverseSrcIP")
	rsrcIP := f.Tag.Get("default")
	conf.ReverseSrcIP = rsrcIP

	f, _ = typ.FieldByName("ReverseDstIP")
	rdstIP := f.Tag.Get("default")
	conf.ReverseDstIP = rdstIP

	return conf
}

func NewNatFlow(conf NatFlowConfig) (*Flow, error) {
	flowspec := flowSpec{
		family:         syscall.AF_INET,
		action:         VR_FLOW_ACTION_NAT,
		srcIP:          net.ParseIP(conf.SrcIP),
		dstIP:          net.ParseIP(conf.DstIP),
		srcPort:        int16(conf.SrcPort),
		dstPort:        int16(conf.DstPort),
		proto:          conf.Protocol,
		nhId:           conf.Nexthop,
		srcNhIndex:     conf.SrcNexthop,
		vrf:            conf.Vrf,
		dstVrf:         conf.Dvrf,
		reverseNhId:    conf.ReverseNexthop,
		flags:          int16(conf.Flags),
		reverseSrcIP:   net.ParseIP(conf.ReverseDstIP),
		reverseDstIP:   net.ParseIP(conf.ReverseSrcIP),
		reverseSrcPort: int16(conf.DstPort),
		reverseDstPort: int16(conf.ReverseSrcPort),
		qosId:          conf.QosId,
		ecmpNhIndex:    conf.EcmpNexthop,
	}

	return NewFlow(&flowspec)
}

// private functions

func ipToULInt64(family int32, ipaddr net.IP) (int64, int64) {
	var upper, lower int64

	if family == syscall.AF_INET {
		ip := binary.LittleEndian.Uint32(ipaddr.To4())
		lower = int64(ip)
	} else if family == syscall.AF_INET6 {
		ip := ipaddr.To16()
		upper = int64(binary.LittleEndian.Uint64(ip[0:8]))
		lower = int64(binary.LittleEndian.Uint64(ip[8:]))
	}

	return upper, lower
}
