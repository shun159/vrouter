package vr

import (
	"reflect"
	"strconv"
)

// Virtual Interface Base struct
type Nexthop struct {
	*VrNexthopReq
}

func NewNextHop(
	nh_type uint8, nh_id int32, nh_family int8,
	nh_vrf int32, nh_flags uint32, encap_oif_id []int32,
	encap []byte, encap_family int32) *Nexthop {
	encap_data := make([]int8, len(encap))
	for idx, b := range encap {
		encap_data[idx] = int8(b)
	}

	nh := &Nexthop{}
	nh.VrNexthopReq = NewVrNexthopReq()
	nh.HOp = SandeshOp(SANDESH_OPER_ADD)
	nh.NhrID = nh_id
	nh.NhrFamily = nh_family
	nh.NhrType = int8(nh_type)
	nh.NhrVrf = nh_vrf
	nh.NhrFlags = int32(nh_flags) | NH_FLAG_VALID
	nh.NhrEncapOifID = encap_oif_id
	nh.NhrEncap = encap_data
	nh.NhrEncapLen = int32(len(encap_data))
	nh.NhrEncapFamily = encap_family
	return nh
}

// Encap nexthop config
type EncapNexthopConfig struct {
	// Mandatory parameters
	Idx             int32
	EncapOuterVifId []int32
	Encap           []byte
	// Optional Parameters
	Flags       uint32 `default:"1"` // NH_FLAG_VALID
	Family      int8   `default:"2"` // syscall.AF_INET
	EncapFamily int32
	Vrf         int32
}

// Create Encap Nexthop config with default values
func NewEncapNexthopConfig() *EncapNexthopConfig {
	var f reflect.StructField
	conf := EncapNexthopConfig{}
	typ := reflect.TypeOf(EncapNexthopConfig{})

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = uint32(flags)

	f, _ = typ.FieldByName("Family")
	family, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Family = int8(family)

	return &conf
}

// Create Encap nexthop
func NewEncapNexthop(conf *EncapNexthopConfig) (*Nexthop, error) {
	return NewNextHop(
		NH_TYPE_ENCAP,
		conf.Idx,
		conf.Family,
		conf.Vrf,
		conf.Flags,
		conf.EncapOuterVifId,
		conf.Encap,
		conf.EncapFamily,
	), nil
}

// Encap nexthop config
type ReceiveNexthopConfig struct {
	// Mandatory parameters
	Idx             int32
	EncapOuterVifId []int32
	Encap           []byte
	// Optional Parameters
	Flags       uint32 `default:"1"` // NH_FLAG_VALID
	Family      byte   `default:"2"` // syscall.AF_INET
	EncapFamily int32
	Vrf         int32
}

// Create Encap Nexthop config with default values
func NewReceiveNexthopConfig() *ReceiveNexthopConfig {
	var f reflect.StructField
	conf := ReceiveNexthopConfig{}
	typ := reflect.TypeOf(ReceiveNexthopConfig{})

	f, _ = typ.FieldByName("Flags")
	flags, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = uint32(flags)

	f, _ = typ.FieldByName("Family")
	family, _ := strconv.Atoi(f.Tag.Get("default"))
	conf.Flags = uint32(family)

	return &conf
}

// Create Encap nexthop
func NewReceiveNexthop(conf *ReceiveNexthopConfig) (*Nexthop, error) {
	return NewNextHop(
		NH_TYPE_RCV,
		conf.Idx,
		int8(conf.Family),
		conf.Vrf,
		conf.Flags,
		conf.EncapOuterVifId,
		conf.Encap,
		conf.EncapFamily,
	), nil
}
