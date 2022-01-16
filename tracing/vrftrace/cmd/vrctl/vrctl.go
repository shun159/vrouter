package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/shun159/vrftrace/vr"
)

func linkFwdNatFlow(nl *vr.Netlink, flow1 vr.VrFlowResponse, rflow vr.VrFlowResponse) vr.VrFlowResponse {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	flow_conf := vr.NewNatFlowConfig()
	flow_conf.SrcIP = "8.0.0.1"
	flow_conf.DstIP = "8.0.0.3"
	flow_conf.SrcPort = 53
	flow_conf.DstPort = 60185
	flow_conf.Protocol = syscall.IPPROTO_UDP
	flow_conf.Nexthop = 5
	flow_conf.SrcNexthop = 16
	flow_conf.Vrf = 0
	flow_conf.Dvrf = 2
	flow_conf.ReverseSrcIP = "1.1.1.5"
	flow_conf.ReverseDstIP = "169.254.169.7"
	flow_conf.ReverseNexthop = 21
	flow_conf.ReverseSrcPort = 33596
	flow_conf.Flags =
		vr.VR_FLOW_FLAG_VRFT |
			vr.VR_FLOW_FLAG_SNAT |
			vr.VR_FLOW_FLAG_DNAT |
			vr.VR_FLOW_FLAG_DPAT |
			vr.VR_FLOW_FLAG_LINK_LOCAL |
			vr.VR_FLOW_FLAG_ACTIVE |
			vr.VR_RFLOW_VALID
	flow, err := vr.NewNatFlow(flow_conf)
	flow.FrIndex = flow1.FrespIndex
	flow.FrRindex = rflow.FrespIndex
	flow.FrGenID = rflow.FrespGenID
	flow.FrUnderlayEcmpIndex = -1
	flow.FrQosID = -1
	if err != nil {
		os.Exit(1)
	}

	s_req := flow.VrFlowReq
	stream := nl.SendAsync(s_req)
	resp := <-stream

	flow_resp := vr.NewVrResponse()
	nl.Transport.Buffer = resp.Buffer
	flow_resp.Read(nl.Ctx, nl.Protocol)

	flow_resp2 := vr.NewVrFlowResponse()
	flow_resp2.Read(nl.Ctx, nl.Protocol)

	return *flow_resp2
}

func createFwdNatFlow(nl *vr.Netlink) vr.VrFlowResponse {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	flow_conf := vr.NewNatFlowConfig()
	flow_conf.SrcIP = "8.0.0.1"
	flow_conf.DstIP = "8.0.0.3"
	flow_conf.SrcPort = 53
	flow_conf.DstPort = 60185
	flow_conf.Protocol = syscall.IPPROTO_UDP
	flow_conf.Nexthop = 5
	flow_conf.SrcNexthop = 16
	flow_conf.Vrf = 0
	flow_conf.Dvrf = 2
	flow_conf.ReverseSrcIP = "1.1.1.5"
	flow_conf.ReverseDstIP = "169.254.169.7"
	flow_conf.ReverseNexthop = 21
	flow_conf.ReverseSrcPort = 33596
	flow_conf.Flags =
		vr.VR_FLOW_FLAG_VRFT |
			vr.VR_FLOW_FLAG_SNAT |
			vr.VR_FLOW_FLAG_DNAT |
			vr.VR_FLOW_FLAG_DPAT |
			vr.VR_FLOW_FLAG_LINK_LOCAL |
			vr.VR_FLOW_FLAG_ACTIVE
	flow, err := vr.NewNatFlow(flow_conf)
	flow.FrIndex = -1
	flow.FrRindex = -1
	flow.FrUnderlayEcmpIndex = -1
	flow.FrQosID = -1
	if err != nil {
		os.Exit(1)
	}

	s_req := flow.VrFlowReq
	stream := nl.SendAsync(s_req)
	resp := <-stream

	flow_resp := vr.NewVrResponse()
	nl.Transport.Buffer = resp.Buffer
	flow_resp.Read(nl.Ctx, nl.Protocol)

	flow_resp2 := vr.NewVrFlowResponse()
	flow_resp2.Read(nl.Ctx, nl.Protocol)

	return *flow_resp2
}

func createReverseNatFlow(nl *vr.Netlink, rflow vr.VrFlowResponse) vr.VrFlowResponse {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	flow_conf := vr.NewNatFlowConfig()
	flow_conf.SrcIP = "1.1.1.5"
	flow_conf.DstIP = "169.254.159.7"
	flow_conf.SrcPort = 33596
	flow_conf.DstPort = 53
	flow_conf.Protocol = syscall.IPPROTO_UDP
	flow_conf.Nexthop = 21
	flow_conf.SrcNexthop = 21
	flow_conf.Dvrf = 0
	flow_conf.Vrf = 2
	flow_conf.ReverseSrcIP = "8.0.0.1"
	flow_conf.ReverseDstIP = "8.0.0.3"
	flow_conf.ReverseNexthop = 5
	flow_conf.ReverseSrcPort = 53
	flow_conf.Flags =
		vr.VR_RFLOW_VALID |
			vr.VR_FLOW_FLAG_VRFT |
			vr.VR_FLOW_FLAG_SNAT |
			vr.VR_FLOW_FLAG_DNAT |
			vr.VR_FLOW_FLAG_SPAT |
			vr.VR_FLOW_FLAG_ACTIVE
	flow, err := vr.NewNatFlow(flow_conf)
	flow.FrOp = vr.FlowOp_FLOW_SET
	flow.FrIndex = -1
	flow.FrRindex = rflow.FrespIndex
	flow.FrGenID = rflow.FrespGenID
	flow.FrUnderlayEcmpIndex = -1
	flow.FrQosID = -1
	flow.FrAction = vr.VR_FLOW_ACTION_FORWARD
	if err != nil {
		os.Exit(1)
	}

	s_req := flow.VrFlowReq
	stream := nl.SendAsync(s_req)
	resp := <-stream

	flow_resp := vr.NewVrResponse()
	nl.Transport.Buffer = resp.Buffer
	flow_resp.Read(nl.Ctx, nl.Protocol)

	flow_resp2 := vr.NewVrFlowResponse()
	flow_resp2.Read(nl.Ctx, nl.Protocol)

	return *flow_resp2
}

func createTenantRoute(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	rt_conf := vr.NewInetRouteConfig()
	rt_conf.IPAddress = "1.1.1.5"
	rt_conf.NhIdx = 21
	rt_conf.Vrf = 2
	rt_conf.PrefixLen = 32
	rt_conf.LabelFlag = vr.VR_RT_ARP_PROXY_FLAG
	rt, err := vr.NewInetRoute(rt_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := rt.VrRouteReq
	stream := nl.SendAsync(s_req)

	<-stream
}

func createFabricRoute(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	rt_conf := vr.NewInetRouteConfig()
	rt_conf.IPAddress = "8.0.0.3"
	rt_conf.Vrf = 0
	rt_conf.NhIdx = 10
	rt_conf.PrefixLen = 32
	rt_conf.LabelFlag = vr.VR_RT_ARP_TRAP_FLAG
	rt, err := vr.NewInetRoute(rt_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := rt.VrRouteReq
	stream := nl.SendAsync(s_req)

	<-stream
}

func createCacheAllNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewReceiveNexthopConfig()
	nh_conf.Idx = 10
	nh_conf.Vrf = 1
	nh_conf.EncapOifId = []int32{1}
	nh_conf.Flags = vr.NH_FLAG_RELAXED_POLICY
	nh, err := vr.NewReceiveNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req)
	<-stream
}

func createTenantVifNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{3}
	nh_conf.EncapFamily = vr.VR_ETH_PROTO_ARP
	nh_conf.Flags = vr.NH_FLAG_POLICY_ENABLED
	nh_conf.Encap = []byte{
		0x02, 0xc2, 0x23, 0x4c, 0xd0, 0x55,
		0x00, 0x00, 0x5e, 0x00, 0x01, 0x00,
		0x08, 0x00,
	}
	nh_conf.Idx = 21
	nh_conf.Vrf = 2
	nh, err := vr.NewEncapNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req)
	<-stream
}

func createFabricVifNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{0}
	nh_conf.EncapFamily = vr.VR_ETH_PROTO_ARP
	nh_conf.Encap = []byte{
		0x90, 0xe2, 0xba, 0x84, 0x48, 0x88,
		0xce, 0xc5, 0x38, 0xb7, 0x64, 0xb3,
		0x08, 0x00,
	}
	nh_conf.Idx = 16
	nh_conf.Vrf = 0
	nh, err := vr.NewEncapNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req)
	<-stream
}

func createVhostVifNh(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	nh_conf := vr.NewEncapNexthopConfig()
	nh_conf.EncapOuterVifId = []int32{1}
	nh_conf.Flags = vr.NH_FLAG_POLICY_ENABLED
	nh_conf.EncapFamily = vr.VR_ETH_PROTO_ARP
	nh_conf.Encap = []byte{
		0x00, 0x1b, 0x21, 0xbb, 0xf9, 0x46,
		0xce, 0xc5, 0x38, 0xb7, 0x64, 0xb3,
		0x08, 0x00,
	}
	nh_conf.Idx = 5
	nh_conf.Vrf = 0
	nh, err := vr.NewEncapNexthop(nh_conf)
	if err != nil {
		os.Exit(1)
	}

	s_req := nh.VrNexthopReq
	stream := nl.SendAsync(s_req)
	<-stream
}

func createAgentVif(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	agent_conf := vr.NewAgentVifConfig()
	agent_conf.Idx = 2
	agent_conf.Name = "pkt0"
	agent_conf.Flags = vr.VIF_FLAG_L3_ENABLED | vr.VIF_FLAG_DHCP_ENABLED
	agent, err := vr.NewAgentVif(agent_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := agent.VrInterfaceReq
	stream := nl.SendAsync(s_req)
	<-stream
}

func createVirtualVif(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	virtual_conf := vr.NewVirtualVifConfig()
	virtual_conf.Idx = 3
	virtual_conf.IpAddr = "1.1.1.5"
	virtual_conf.Name = "tap0"
	virtual_conf.MacAddr = "00:00:5e:00:01:00"
	virtual_conf.Nexthop = 21
	virtual_conf.Transport = vr.VIF_TRANSPORT_ETH
	virtual_conf.Flags = vr.VIF_FLAG_POLICY_ENABLED | vr.VIF_FLAG_L2_ENABLED | vr.VIF_FLAG_L3_ENABLED | vr.VIF_FLAG_DHCP_ENABLED
	virtual_conf.Vrf = 2
	virtual_conf.McastVrf = 2
	virtual, err := vr.NewVirtualVif(virtual_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := virtual.VrInterfaceReq
	stream := nl.SendAsync(s_req)
	resp := <-stream

	vr_resp := vr.NewVrResponse()
	nl.Transport.Buffer = resp.Buffer
	vr_resp.Read(nl.Ctx, nl.Protocol)
	fmt.Printf("vr_resp: %+v\n", vr_resp)
}

func createVhostVif(nl *vr.Netlink) {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	vhost_conf := vr.NewVhostVifConfig()
	vhost_conf.Idx = 1
	vhost_conf.IpAddr = "8.0.0.3"
	vhost_conf.Name = "vhost0"
	vhost_conf.MacAddr = "ce:c5:38:b7:64:b3"
	vhost_conf.NextHop = 5
	vhost_conf.Flags = vr.VIF_FLAG_L3_ENABLED | vr.VIF_FLAG_XCONNECT
	vhost_conf.XConnect = []string{"fabric0"}
	vhost_conf.Transport = vr.VIF_TRANSPORT_PMD
	vhost, err := vr.NewVhostVif(vhost_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := vhost.VrInterfaceReq
	stream := nl.SendAsync(s_req)
	resp := <-stream

	vr_resp := vr.NewVrResponse()
	nl.Transport.Buffer = resp.Buffer
	vr_resp.Read(nl.Ctx, nl.Protocol)
	fmt.Printf("vr_resp: %+v\n", vr_resp)
}

func createFabricVif(nl *vr.Netlink) {
	fabric_conf := vr.NewFabricVifConfig()
	fabric_conf.Idx = 0
	fabric_conf.Name = "fabric0"
	fabric_conf.MacAddr = "ce:c5:38:b7:64:b3"
	fabric_conf.Flags = vr.VIF_FLAG_L3_ENABLED | vr.VIF_FLAG_L2_ENABLED | vr.VIF_FLAG_VHOST_PHYS
	fabric_conf.Transport = vr.VIF_TRANSPORT_PMD
	fabric, err := vr.NewFabricVif(fabric_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := fabric.VrInterfaceReq
	stream := nl.SendAsync(s_req)
	<-stream
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

	// Routes
	createFabricRoute(nl)
	createTenantRoute(nl)

	// flows
	flow := createFwdNatFlow(nl)
	rflow := createReverseNatFlow(nl, flow)
	linkFwdNatFlow(nl, flow, rflow)

}
