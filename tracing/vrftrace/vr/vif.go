package vr

//#include <net/if.h>
//#include <stdlib.h>
import "C"

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/apache/thrift/lib/go/thrift"
)

// Virtual Interface Base struct
type Vif struct {
	*VrInterfaceReq
	*thrift.TMemoryBuffer
	*TSandeshProtocol
	context.Context
}

// Create virtual interface base struct
func NewVif(oper, idx, viftype int32, name, ipaddr, macaddr string, transport int8) (*Vif, error) {
	hwaddr, err := net.ParseMAC(macaddr)
	if err != nil {
		return nil, err
	}

	hwaddr_thrift := make([]int8, len(hwaddr))
	for idx, b := range hwaddr {
		hwaddr_thrift[idx] = int8(b)
	}

	vif := &Vif{}
	vif.VrInterfaceReq = &VrInterfaceReq{}
	vif.VrInterfaceReq.HOp = SandeshOp(oper)
	vif.VrInterfaceReq.VifrIdx = idx
	vif.VrInterfaceReq.VifrType = viftype
	vif.VrInterfaceReq.VifrName = name
	vif.VrInterfaceReq.VifrTransport = transport
	vif.VrInterfaceReq.VifrIP = ipAddrToInt32(net.ParseIP(ipaddr))
	vif.VrInterfaceReq.VifrMac = hwaddr_thrift
	vif.VrInterfaceReq.VifrOsIdx = ifNameToIndex(name)
	vif.TMemoryBuffer = thrift.NewTMemoryBuffer()
	vif.TSandeshProtocol = NewTSandeshProtocolTransport(vif.TMemoryBuffer)
	vif.Context = context.Background()

	return vif, nil
}

// AgentVif config
type AgentVifConfig struct {
	// Mandatory Parameters
	Name string
	Idx  int32
	// Optional Parameters
	Vrf      int32 `default:"65535"`
	McastVrf int32 `default:"65535"`
	Mtu      int32 `default:"1514"`
	Flags    int32 `default:"320"`
}

// Create agentif config with default values
func NewAgentVifConfig() *AgentVifConfig {
	var f reflect.StructField
	conf := AgentVifConfig{}
	typ := reflect.TypeOf(AgentVifConfig{})

	f, _ = typ.FieldByName("McastVrf")
	mcast_vrf, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.McastVrf = int32(mcast_vrf)

	f, _ = typ.FieldByName("Vrf")
	vrf, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Vrf = int32(vrf)

	f, _ = typ.FieldByName("Mtu")
	mtu, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Mtu = int32(mtu)

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = int32(flags)

	return &conf
}

// Create VhostVif
func NewAgentVif(conf *AgentVifConfig) (*Vif, error) {
	vif, err := NewVif(
		SANDESH_OPER_ADD,
		conf.Idx,
		VIF_TYPE_AGENT,
		conf.Name,
		"0.0.0.0",
		"00:00:5e:00:01:00",
		VIF_TRANSPORT_SOCKET,
	)

	if err != nil {
		return nil, err
	}

	vif.VifrVrf = conf.Vrf
	vif.VifrMcastVrf = conf.McastVrf
	vif.VifrMtu = conf.Mtu
	vif.VifrFlags = conf.Flags

	return vif, nil
}

// Vhost config
type VhostVifConfig struct {
	// Mandatory Parameters
	Idx     int32
	Name    string
	IpAddr  string
	MacAddr string
	// Optional Parameters
	NextHop   int32
	McastVrf  uint32 `default:"65535"`
	Mtu       int32  `default:"1514"`
	Flags     int32  `default:"384"`
	Transport int8   `default:"1"`
	Vrf       int32
	XConnect  []string
}

// Create vhost config with default values
func NewVhostVifConfig() *VhostVifConfig {
	var f reflect.StructField
	conf := VhostVifConfig{}
	typ := reflect.TypeOf(VhostVifConfig{})

	f, _ = typ.FieldByName("McastVrf")
	mcast_vrf, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.McastVrf = uint32(mcast_vrf)

	f, _ = typ.FieldByName("Mtu")
	mtu, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Mtu = int32(mtu)

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = int32(flags)

	f, _ = typ.FieldByName("Transport")
	trans, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Transport = int8(trans)

	f, _ = typ.FieldByName("IpAddr")
	ipaddr := f.Tag.Get("default")
	conf.IpAddr = ipaddr

	return &conf
}

// Create VhostVif
func NewVhostVif(conf *VhostVifConfig) (*Vif, error) {
	vif, err := NewVif(
		SANDESH_OPER_ADD,
		conf.Idx,
		VIF_TYPE_HOST,
		conf.Name,
		conf.IpAddr,
		conf.MacAddr,
		conf.Transport,
	)

	if err != nil {
		return nil, err
	}

	vif.VifrNhID = conf.NextHop
	vif.VifrVrf = conf.Vrf
	vif.VifrCrossConnectIdx = ifNamesToIndexes(conf.XConnect)
	vif.VifrMcastVrf = int32(conf.McastVrf)
	vif.VifrMtu = conf.Mtu
	vif.VifrFlags = conf.Flags

	return vif, nil
}

// FabricVif config
type FabricVifConfig struct {
	// Mandatory Parameters
	Idx     int32
	Name    string
	MacAddr string
	// Optional Parameters
	IpAddr    string `default:"0.0.0.0"`
	McastVrf  uint32 `default:"65535"`
	Mtu       int32  `default:"1514"`
	Flags     int32  `default:"322"`
	Transport int8   `default:"1"`
	Vrf       int32
}

// Create vhost config with default values
func NewFabricVifConfig() FabricVifConfig {
	var f reflect.StructField
	conf := FabricVifConfig{}
	typ := reflect.TypeOf(FabricVifConfig{})

	f, _ = typ.FieldByName("McastVrf")
	mcast_vrf, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.McastVrf = uint32(mcast_vrf)

	f, _ = typ.FieldByName("Mtu")
	mtu, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Mtu = int32(mtu)

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = int32(flags)

	f, _ = typ.FieldByName("Transport")
	trans, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Transport = int8(trans)

	f, _ = typ.FieldByName("IpAddr")
	ipaddr := f.Tag.Get("default")
	conf.IpAddr = ipaddr

	return conf
}

// Create VhostVif
func NewFabricVif(conf FabricVifConfig) (*Vif, error) {
	vif, err := NewVif(
		SANDESH_OPER_ADD,
		conf.Idx,
		VIF_TYPE_PHYSICAL,
		conf.Name,
		conf.IpAddr,
		conf.MacAddr,
		conf.Transport,
	)

	if err != nil {
		return nil, err
	}

	vif.VifrVrf = conf.Vrf
	vif.VifrMcastVrf = int32(conf.McastVrf)
	vif.VifrMtu = conf.Mtu
	vif.VifrFlags = conf.Flags

	return vif, nil
}

// VirtualVif config
type VirtualVifConfig struct {
	// Mandatory Parameters
	Idx     int32
	Name    string
	MacAddr string `default:"00:00:00:00:00:00"`
	IpAddr  string `default:"0.0.0.0"`
	// Optional Parameters
	Nexthop   int32
	Mtu       int32 `default:"1514"`
	Flags     int32 `default:"1"`
	Transport int8  `default:"1"`
	Vrf       int32
	McastVrf  uint32 `default:"65535"`
}

// Create vhost config with default values
func NewVirtualVifConfig() VirtualVifConfig {
	var f reflect.StructField
	conf := VirtualVifConfig{}
	typ := reflect.TypeOf(VirtualVifConfig{})

	f, _ = typ.FieldByName("McastVrf")
	mcast_vrf, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.McastVrf = uint32(mcast_vrf)

	f, _ = typ.FieldByName("Mtu")
	mtu, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Mtu = int32(mtu)

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = int32(flags)

	f, _ = typ.FieldByName("Transport")
	trans, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Transport = int8(trans)

	f, _ = typ.FieldByName("IpAddr")
	ipaddr := f.Tag.Get("default")
	conf.IpAddr = ipaddr

	return conf
}

// Create VhostVif
func NewVirtualVif(conf VirtualVifConfig) (*Vif, error) {
	vif, err := NewVif(
		SANDESH_OPER_ADD,
		conf.Idx,
		VIF_TYPE_VIRTUAL,
		conf.Name,
		conf.IpAddr,
		conf.MacAddr,
		conf.Transport,
	)

	if err != nil {
		return nil, err
	}
	vif.VifrNhID = conf.Nexthop
	vif.VifrMtu = conf.Mtu
	vif.VifrFlags = conf.Flags
	vif.VifrVrf = conf.Vrf
	vif.VifrMcastVrf = int32(conf.McastVrf)

	return vif, nil
}

// Serialize Vif struct into Sandesh format binary
func (vif *Vif) ToBinary(ctx context.Context, proto *TSandeshProtocol) ([]byte, error) {
	s_req := vif.VrInterfaceReq
	if err := s_req.Write(ctx, proto); err != nil {
		return []byte{}, err
	} else {
		return vif.TMemoryBuffer.Bytes(), nil
	}
}

// Helper functions

func ifNamesToIndexes(names []string) []int32 {
	indexes := []int32{}
	for _, name := range names {
		idx := ifNameToIndex(name)
		if idx < 1 {
			continue
		}

		indexes = append(indexes, idx)
	}

	return indexes
}

func ifNameToIndex(name string) int32 {
	c_name := C.CString(name)
	ifindex := C.if_nametoindex(c_name)
	defer C.free(unsafe.Pointer(c_name))
	if ifidx := int32(ifindex); ifidx > 0 {
		return ifidx
	}
	return 0
}

func ipAddrToInt32(ip net.IP) int32 {
	if len(ip) == 16 {
		return int32(binary.LittleEndian.Uint32(ip[12:16]))
	}
	return int32(binary.LittleEndian.Uint32(ip))
}
