package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"github.com/shun159/vrftrace/vr"
)

func createInetFlow0() *vr.Flow {
	data := []uint8{0, 53}
	srcPort := binary.LittleEndian.Uint16(data)

	data2 := []uint8{235, 25}
	dstPort := binary.LittleEndian.Uint16(data2)

	flow_conf := vr.NewInetFlowConfig()
	flow_conf.Index = -1
	flow_conf.Action = vr.VR_FLOW_ACTION_FORWARD
	flow_conf.SrcIP = "1.1.1.1"
	flow_conf.DstIP = "1.1.1.2"
	flow_conf.Protocol = syscall.IPPROTO_UDP
	flow_conf.SrcPort = srcPort
	flow_conf.DstPort = dstPort
	flow_conf.Nexthop = 49
	flow, _ := vr.NewInetFlow(flow_conf)
	return flow
}

func createBrRoute0() *vr.Route {
	rt_conf := vr.NewBridgeRouteConfig()
	rt_conf.Vrf = 0
	rt_conf.NhIdx = 49
	rt_conf.MacAddress = "de:ad:be:ef:02:02"
	rt, _ := vr.NewBridgeRoute(rt_conf)
	return rt
}

func createBrRoute1() *vr.Route {
	rt_conf := vr.NewBridgeRouteConfig()
	rt_conf.Vrf = 0
	rt_conf.NhIdx = 47
	rt_conf.MacAddress = "de:ad:be:ef:02:03"
	rt, _ := vr.NewBridgeRoute(rt_conf)
	return rt
}

func createNexthopTap0() *vr.Nexthop {
	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{3}
	nh_conf.Family = syscall.AF_BRIDGE
	nh_conf.Idx = 49
	nh_conf.Encap = []byte{
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x02,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0x08, 0x00,
	}
	nh, _ := vr.NewEncapNexthop(nh_conf)
	return nh
}

func createNexthopTap1() *vr.Nexthop {
	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{4}
	nh_conf.Family = syscall.AF_BRIDGE
	nh_conf.Idx = 47
	nh_conf.Encap = []byte{
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x02,
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
		0x08, 0x00,
	}
	nh, _ := vr.NewEncapNexthop(nh_conf)
	return nh
}

func createAgentVif() *vr.Vif {
	agent_conf := vr.NewAgentVifConfig()
	agent_conf.Idx = 2
	agent_conf.Name = "pkt0"
	agent, _ := vr.NewAgentVif(agent_conf)

	return agent
}

func createVirtualVif_1() *vr.Vif {
	virtual_conf := vr.NewVirtualVifConfig()
	virtual_conf.Idx = 3
	virtual_conf.IpAddr = "1.1.1.5"
	virtual_conf.Name = "tap0"
	virtual_conf.MacAddr = "de:ad:be:ef:00:02"
	virtual_conf.Nexthop = 49
	virtual_conf.Vrf = 0
	virtual_conf.McastVrf = 2
	virtual_conf.Flags = vr.VIF_FLAG_L2_ENABLED | vr.VIF_FLAG_POLICY_ENABLED
	virtual, _ := vr.NewVirtualVif(virtual_conf)

	return virtual
}

func createVirtualVif_2() *vr.Vif {
	virtual_conf := vr.NewVirtualVifConfig()
	virtual_conf.Idx = 4
	virtual_conf.IpAddr = "1.1.1.6"
	virtual_conf.Name = "tap1"
	virtual_conf.MacAddr = "de:da:eb:fe:00:03"
	virtual_conf.Nexthop = 47
	virtual_conf.Vrf = 0
	virtual_conf.McastVrf = 2
	virtual_conf.Flags = vr.VIF_FLAG_L2_ENABLED | vr.VIF_FLAG_POLICY_ENABLED
	virtual, _ := vr.NewVirtualVif(virtual_conf)

	return virtual
}

func createVhostVif() *vr.Vif {
	vhost_conf := vr.NewVhostVifConfig()
	vhost_conf.Idx = 1
	vhost_conf.IpAddr = "8.0.0.3"
	vhost_conf.Name = "vhost0"
	vhost_conf.MacAddr = "ce:c5:38:b7:64:b3"
	vhost_conf.NextHop = 5
	vhost_conf.Flags = vr.VIF_FLAG_XCONNECT
	vhost_conf.XConnect = []string{"fabric0"}
	vhost, _ := vr.NewVhostVif(vhost_conf)

	return vhost
}

func createFabricVif() *vr.Vif {
	fabric_conf := vr.NewFabricVifConfig()
	fabric_conf.Idx = 0
	fabric_conf.Name = "fabric0"
	fabric_conf.MacAddr = "ce:c5:38:b7:64:b3"
	fabric_conf.Flags = vr.VIF_FLAG_VHOST_PHYS
	fabric, _ := vr.NewFabricVif(fabric_conf)

	return fabric
}

func createRoute(nl *vr.Netlink) {
	routes := []*vr.Route{
		createBrRoute0(),
		createBrRoute1(),
	}

	for _, route := range routes {
		s_req := route.VrRouteReq
		<-nl.SendAsync(s_req)
	}
}

func createFlow(nl *vr.Netlink) {
	flows := []*vr.Flow{
		createInetFlow0(),
	}

	for _, flow := range flows {
		s_req := flow.VrFlowReq
		resp := <-nl.SendAsync(s_req)
		vr_resp := vr.NewVrResponse()
		nl.Transport.Buffer = resp.Buffer
		vr_resp.Read(nl.Ctx, nl.Protocol)
		if vr_resp.RespCode != 0 {
			fmt.Printf("Failed to create Flow(%d)\n", vr_resp.RespCode)
			os.Exit(1)
		}
	}
}

func createNh(nl *vr.Netlink) {
	nexthops := []*vr.Nexthop{
		createNexthopTap0(),
		createNexthopTap1(),
	}

	for _, nexthop := range nexthops {
		s_req := nexthop.VrNexthopReq
		resp := <-nl.SendAsync(s_req)
		vr_resp := vr.NewVrResponse()
		nl.Transport.Buffer = resp.Buffer
		vr_resp.Read(nl.Ctx, nl.Protocol)
		if vr_resp.RespCode != 0 {
			fmt.Printf("Failed to create NextHop(%d)\n", nexthop.NhrID)
			os.Exit(1)
		}
	}
}

func createVif(nl *vr.Netlink) {
	// VIF
	vifs := []*vr.Vif{
		createAgentVif(),     // pkt0
		createFabricVif(),    // fabric0
		createVhostVif(),     // vhost0
		createVirtualVif_1(), // tap0
		createVirtualVif_2(), // tap1
	}

	for _, vif := range vifs {
		s_req := vif.VrInterfaceReq
		resp := <-nl.SendAsync(s_req)
		vr_resp := vr.NewVrResponse()
		nl.Transport.Buffer = resp.Buffer
		vr_resp.Read(nl.Ctx, nl.Protocol)
		if vr_resp.RespCode != 0 {
			fmt.Printf("Failed to create VIF(%s) %d\n", vif.VifrName, vr_resp.RespCode)
			os.Exit(1)
		}
	}
}

func main() {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	createVif(nl)
	createNh(nl)
	createRoute(nl)
	createFlow(nl)
}
