package vr

// VXLAN interface
type Vxlan struct {
	*VrVxlanReq
}

func NewVxlan(rid int16, vnid, nhid int32) (*Vxlan, error) {
	vxlan := &Vxlan{}
	vxlan.VrVxlanReq = NewVrVxlanReq()
	vxlan.HOp = SandeshOp_ADD
	vxlan.VxlanrRid = rid
	vxlan.VxlanrVnid = vnid
	vxlan.VxlanrNhid = nhid
	return vxlan, nil
}
