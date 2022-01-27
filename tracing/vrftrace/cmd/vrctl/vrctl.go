/*
Demo Configuration
----

### Virtual Interfaces

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3, L2=Layer 2
       D=DHCP, Vp=Vhost Physical, Pr=Promiscuous, Vnt=Native Vlan Tagged
       Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface, Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload, Df=Drop New Flows, L=MAC Learning Enabled
       Proxy=MAC Requests Proxied Always, Er=Etree Root, Mn=Mirror without Vlan Tag, HbsL=HBS Left Intf
       HbsR=HBS Right Intf, Ig=Igmp Trap Enabled, Ml=MAC-IP Learning Enabled

vif0/2      OS: pkt0
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3D QOS:0 Ref:1
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/3      OS: tap0 NH: 49
            Type:Virtual HWaddr:de:ad:be:ef:00:02 IPaddr:1.1.1.5
            Vrf:0 Mcast Vrf:2 Flags:PL2 QOS:0 Ref:2
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/4      OS: tap1 NH: 47
            Type:Virtual HWaddr:de:da:eb:fe:00:03 IPaddr:1.1.1.6
            Vrf:0 Mcast Vrf:2 Flags:PL2 QOS:0 Ref:2
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/4353   OS: pkt3
            Type:Stats HWaddr:00:00:00:00:00:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3L2 QOS:0 Ref:1
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

### Bridge Entries

root@shun159:/home/shun159/play/openflow/contrail# ./build/debug/vrouter/utils/rt --dump 0 --family bridge
Flags: L=Label Valid, Df=DHCP flood, Mm=Mac Moved, L2c=L2 Evpn Control Word, N=New Entry, Ec=EvpnControlProcessing
vRouter bridge table 0/0
Index       DestMac                  Flags           Label/VNID      Nexthop           Stats
1104        de:ad:be:ef:2:2                                   -           49               0
121388      de:ad:be:ef:2:3                                   -           47               0

### Nexthops

dump_marker: -1
Id:0          Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
              Flags:Valid,

Id:47         Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2          Vrf:0
              Flags:Valid,
              EncapFmly:0000 Oif:4 Len:14
              Encap Data: de ad be ef 01 02 de ad be ef 00 01 08 00

Id:49         Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2          Vrf:0
              Flags:Valid,
              EncapFmly:0000 Oif:3 Len:14
              Encap Data: de ad be ef 01 02 de ad be ef 00 01 08 00


### Flow Entries
Flow table(size 161218560, entries 629760)

Entries: Created 0 Added 1 Deleted 0 Changed 0Processed 0 Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT, L=Link Local Port)
 Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
 Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

    Index                Source:Port/Destination:Port                      Proto(V)
-----------------------------------------------------------------------------------
   427420                1.1.1.1:53                                         17 (0)
                         1.1.1.2:60185
(Gen: 1, K(nh):49, Action:F, Flags:, E:0, QOS:0, S(nh):0,  Stats:0/0,
 SPort 51523, TTL 0, UnderlayEcmpIdx:0, Sinfo 0.0.0.0)

*/

package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/shun159/vrftrace/vr"
)

func createInetFlow0() *vr.Flow {
	flow_conf := vr.NewInetFlowConfig()
	flow_conf.Index = -1
	flow_conf.Action = vr.VR_FLOW_ACTION_FORWARD
	flow_conf.SrcIP = "1.1.1.1"
	flow_conf.DstIP = "1.1.1.2"
	flow_conf.Protocol = syscall.IPPROTO_UDP
	flow_conf.SrcPort = 53
	flow_conf.DstPort = 60185
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
