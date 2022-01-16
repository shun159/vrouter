package vr

import (
	"net"
	"reflect"
	"strconv"
	"syscall"
)

// Virtual Interface Base struct
type Route struct {
	*VrRouteReq
}

// Create Route interface base object
func NewRoute(
	oper, family, vrf int32, prefix []int8, pref_len int32,
	mac string, nh_idx int32, rtr_label_flag int16,
	rtr_label int32,
) (*Route, error) {
	hwaddr := make([]byte, 0)
	prefix_thrift := make([]int8, 0)

	if macaddr, err := net.ParseMAC(mac); err == nil {
		hwaddr = macaddr
	}
	hwaddr_thrift := make([]int8, len(hwaddr))
	for idx, b := range hwaddr {
		hwaddr_thrift[idx] = int8(b)
	}

	route := &Route{}
	route.VrRouteReq = NewVrRouteReq()
	route.HOp = SandeshOp(oper)
	route.RtrFamily = family
	route.RtrVrfID = vrf
	route.RtrMac = hwaddr_thrift
	route.RtrPrefix = prefix_thrift
	route.RtrPrefixLen = int32(len(prefix_thrift)) * 8
	route.RtrNhID = nh_idx
	route.RtrLabelFlags = rtr_label_flag
	route.RtrLabel = rtr_label
	return route, nil
}

// Bridge Route config
type BridgeRouteConfig struct {
	// Mandatory Parameters
	Vrf        int32
	NhIdx      int32
	MacAddress string
}

// Bridge Route config with default values
func NewBridgeRouteConfig() *BridgeRouteConfig {
	c := &BridgeRouteConfig{}
	return c
}

// Create Bridge Route
func NewBridgeRoute(conf *BridgeRouteConfig) (*Route, error) {
	route, _ := NewRoute(
		SANDESH_OPER_ADD,
		syscall.AF_BRIDGE,
		conf.Vrf,
		[]int8{},
		0,
		conf.MacAddress,
		conf.NhIdx,
		0,
		0,
	)
	return route, nil
}

// Inet Route config
type InetRouteConfig struct {
	// Mandatory Parameters
	Vrf        int32
	NhIdx      int32
	IPAddress  string `default:"0.0.0.0"`
	PrefixLen  int32  `default:"32"`
	MacAddress string
	LabelFlag  int16
	Label      int32
}

// Inet Route config with default values
func NewInetRouteConfig() *InetRouteConfig {
	var f reflect.StructField
	conf := InetRouteConfig{}
	typ := reflect.TypeOf(InetRouteConfig{})

	f, _ = typ.FieldByName("IPAddress")
	conf.IPAddress = f.Tag.Get("default")

	f, _ = typ.FieldByName("PrefixLen")
	prefix_len, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.PrefixLen = int32(prefix_len)

	return &conf
}

// Create Inet Route
func NewInetRoute(conf *InetRouteConfig) (*Route, error) {
	t_prefix := net.ParseIP(conf.IPAddress).To4()
	prefix := make([]int8, len(t_prefix))
	for idx, b := range t_prefix {
		prefix[idx] = int8(b)
	}

	route, _ := NewRoute(
		SANDESH_OPER_ADD,
		syscall.AF_INET,
		conf.Vrf,
		prefix,
		conf.PrefixLen,
		conf.MacAddress,
		conf.NhIdx,
		conf.LabelFlag,
		conf.Label,
	)
	return route, nil
}

// Inet6 Route config
type Inet6RouteConfig struct {
	// Mandatory Parameters
	Vrf        int32
	NhIdx      int32
	IPAddress  string `default:"::"`
	PrefixLen  int32  `default:"128"`
	MacAddress string
	LabelFlag  int16
	Label      int32
}

// Bridge Route config with default values
func NewInet6RouteConfig() *Inet6RouteConfig {
	var f reflect.StructField
	conf := Inet6RouteConfig{}
	typ := reflect.TypeOf(Inet6RouteConfig{})

	f, _ = typ.FieldByName("IPAddress")
	conf.IPAddress = f.Tag.Get("default")

	f, _ = typ.FieldByName("PrefixLen")
	prefix_len, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.PrefixLen = int32(prefix_len)

	return &conf
}

// Create Bridge Route
func NewInet6Route(conf *Inet6RouteConfig) (*Route, error) {
	t_prefix := net.ParseIP(conf.IPAddress).To4()
	prefix := make([]int8, len(t_prefix))
	for idx, b := range t_prefix {
		prefix[idx] = int8(b)
	}

	route, _ := NewRoute(
		SANDESH_OPER_ADD,
		syscall.AF_INET6,
		conf.Vrf,
		prefix,
		conf.PrefixLen,
		conf.MacAddress,
		conf.NhIdx,
		conf.LabelFlag,
		conf.Label,
	)
	return route, nil
}
