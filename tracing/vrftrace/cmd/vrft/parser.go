package main

import "C"
import (
	"encoding/binary"

	"github.com/shun159/vrftrace/vr"
)

func parseVifr(b []byte) *vr.VrInterfaceReq {
	vifr := vr.NewVrInterfaceReq()
	vifr.HOp = vr.SandeshOp(b[0:4][0])
	vifr.VifrCore = int32(binary.LittleEndian.Uint32(b[4:8]))
	vifr.VifrType = int32(binary.LittleEndian.Uint32(b[8:12]))
	vifr.VifrFlags = int32(binary.LittleEndian.Uint32(b[12:16]))
	vifr.VifrVrf = int32(binary.LittleEndian.Uint32(b[16:20]))
	vifr.VifrIdx = int32(binary.LittleEndian.Uint32(b[20:24]))
	vifr.VifrRid = int32(binary.LittleEndian.Uint32(b[24:28]))
	vifr.VifrOsIdx = int32(binary.LittleEndian.Uint32(b[28:32]))
	vifr.VifrMtu = int32(binary.LittleEndian.Uint32(b[32:36]))
	vifr.VifrRefCnt = int32(binary.LittleEndian.Uint32(b[36:40]))
	vifr.VifrMarker = int32(binary.LittleEndian.Uint32(b[40:44]))
	vifr.VifrIP = int32(binary.BigEndian.Uint32(b[44:52]))
	vifr.VifrIp6U = int64(binary.BigEndian.Uint64(b[52:60]))
	vifr.VifrIp6L = int64(binary.BigEndian.Uint64(b[60:68]))
	vifr.VifrVlanID = int16(binary.LittleEndian.Uint16(b[68:70]))
	vifr.VifrNhID = int32(binary.LittleEndian.Uint32(b[70:74]))
	vifr.VifrTransport = int8(b[74:75][0])

	return vifr
}

func parseRtr(b []byte) *vr.VrRouteReq {
	rtr := vr.NewVrRouteReq()
	rtr.HOp = vr.SandeshOp(b[0:4][0])
	rtr.RtrVrfID = int32(binary.LittleEndian.Uint32(b[4:8]))
	rtr.RtrFamily = int32(binary.LittleEndian.Uint32(b[8:12]))
	_ = int16(binary.LittleEndian.Uint16(b[12:14])) // pad
	rtr.RtrRid = int16(binary.LittleEndian.Uint16(b[14:16]))
	rtr.RtrNhID = int32(binary.LittleEndian.Uint32(b[16:20]))
	rtr.RtrIndex = int32(binary.LittleEndian.Uint32(b[20:24]))

	return rtr
}

func parseNhr(b []byte) *vr.VrNexthopReq {
	nhr := vr.NewVrNexthopReq()
	nhr.HOp = vr.SandeshOp(b[0:4][0])
	_ = int16(binary.LittleEndian.Uint16(b[4:6])) // pad
	nhr.NhrType = int8(b[6:7][0])
	nhr.NhrFamily = int8(b[7:8][0])
	nhr.NhrID = int32(binary.LittleEndian.Uint32(b[8:12]))
	nhr.NhrRid = int32(binary.LittleEndian.Uint32(b[12:16]))
	nhr.NhrFlags = int32(binary.LittleEndian.Uint32(b[16:20]))

	return nhr
}
