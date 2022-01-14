package main

import (
	"fmt"
	"os"

	"github.com/shun159/vrftrace/vr"
)

func createCacheAllNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewReceiveNexthopConfig()
	nh_conf.Idx = 10
	nh_conf.EncapOuterVifId = []int32{3}
	nh_conf.Flags = vr.NH_FLAG_RELAXED_POLICY
	nh, err := vr.NewReceiveNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create Cache all Nexthop. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createTenantVifNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{4}
	nh_conf.EncapFamily = vr.VR_ETH_PROTO_ARP
	nh_conf.Encap = []byte{
		0x02, 0xc2, 0x23, 0x4c, 0xd0, 0x55,
		0x00, 0x00, 0x5e, 0x00, 0x01, 0x00,
		0x08, 0x00,
	}
	nh_conf.Idx = 21
	nh_conf.Vrf = 0
	nh_conf.Flags = 0x20
	nh, err := vr.NewEncapNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create Tenant VIF Nexthop. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createFabricVifNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{2}
	nh_conf.EncapFamily = vr.VR_ETH_PROTO_ARP
	nh_conf.Encap = []byte{
		0x90, 0xe2, 0xba, 0x84, 0x48, 0x88,
		0x00, 0x1b, 0x21, 0xbb, 0xf9, 0x46,
		0x08, 0x00,
	}
	nh_conf.Idx = 16
	nh_conf.Vrf = 0
	nh_conf.Flags = 0x20
	nh, err := vr.NewEncapNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create Fabric VIF Nexthop. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createVhostVifNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{3}
	nh_conf.EncapFamily = vr.VR_ETH_PROTO_ARP
	nh_conf.Encap = []byte{
		0x00, 0x1b, 0x21, 0xbb, 0xf9, 0x46,
		0x00, 0x1b, 0x21, 0xbb, 0xf9, 0x46,
		0x08, 0x00,
	}
	nh_conf.Idx = 5
	nh_conf.Vrf = 0
	nh_conf.Flags = 0x20
	nh, err := vr.NewEncapNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create Vhost VIF Nexthop. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createAgentVif(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	agent_conf := vr.NewAgentVifConfig()
	agent_conf.Idx = 4
	agent_conf.Name = "pkt0"
	agent_conf.Flags = vr.VIF_FLAG_L3_ENABLED | vr.VIF_FLAG_DHCP_ENABLED
	agent, err := vr.NewAgentVif(agent_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := agent.VrInterfaceReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create AgentVif. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createVirtualVif(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	virtual_conf := vr.NewVirtualVifConfig()
	virtual_conf.Idx = 4
	virtual_conf.IpAddr = "1.1.1.5"
	virtual_conf.Name = "tap0"
	virtual_conf.MacAddr = "00:00:5e:00:01:00"
	virtual_conf.Nexthop = 21
	virtual_conf.Vrf = 2
	virtual_conf.McastVrf = 2
	virtual, err := vr.NewVirtualVif(virtual_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := virtual.VrInterfaceReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create VirtualVif. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createVhostVif(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	vhost_conf := vr.NewVhostVifConfig()
	vhost_conf.Idx = 3
	vhost_conf.IpAddr = "8.0.0.3"
	vhost_conf.Name = "eni1np1"
	vhost_conf.MacAddr = "00:1b:21:bb:f9:46"
	vhost_conf.NextHop = 5
	vhost_conf.XConnect = []string{"fabric0"}
	vhost, err := vr.NewVhostVif(vhost_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := vhost.VrInterfaceReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create VhostVif. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func createFabricVif(nl *vr.Netlink) {
	fabric_conf := vr.NewFabricVifConfig()
	fabric_conf.Idx = 2
	fabric_conf.Name = "fabric0"
	fabric_conf.MacAddr = "0e:8d:29:51:91:c3"
	fabric_conf.Flags = vr.VIF_FLAG_L3_ENABLED | vr.VIF_FLAG_DHCP_ENABLED | vr.VIF_FLAG_XCONNECT
	fabric, err := vr.NewFabricVif(fabric_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := fabric.VrInterfaceReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Failed to create FabricVif. code: %+v\n", vr_resp.RespCode)
		os.Exit(1)
	}
}

func main() {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	// VIF
	createAgentVif(nl)   // pkt0
	createFabricVif(nl)  // fabric0
	createVhostVif(nl)   // vhost0
	createVirtualVif(nl) // tap0

	// Nexthop
	createTenantVifNh(nl) // vif nexthop
	createVhostVifNh(nl)  // vhost0 nexthop
	createFabricVifNh(nl) // fabric nexthop
	createCacheAllNh(nl)
}
