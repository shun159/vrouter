package main

import (
	"context"
	"fmt"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/shun159/vrftrace/gen-go/vr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const NL_ATTR_VR_MESSAGE_PROTOCOL int = 1
const SANDESH_REQUEST = 1
const VROUTER_GENETLINK_FAMILY_NAME = "vrouter"

type NlClient struct {
	Handler  *netlink.Handle
	Family   *netlink.GenlFamily
	Tranport *thrift.TMemoryBuffer
	Protocol *TSandeshProtocol
	Context  context.Context
}

func initClient() (*NlClient, error) {
	cl := &NlClient{}
	cl.initSerializer()
	if err := cl.initNlClient(); err != nil {
		return nil, err
	}

	return cl, nil
}

func (cl *NlClient) initSerializer() {
	cl.Context = context.TODO()
	cl.Tranport = thrift.NewTMemoryBuffer()
	cl.Protocol = NewTSandeshProtocolTransport(cl.Tranport)
}

func (cl *NlClient) initNlClient() error {
	handle, err := netlink.NewHandle(unix.NETLINK_GENERIC)
	if err != nil {
		return err
	}

	family, err := handle.GenlFamilyGet(VROUTER_GENETLINK_FAMILY_NAME)
	if err != nil {
		return err
	}

	cl.Handler = handle
	cl.Family = family

	return nil
}

func (cl *NlClient) buildNlAttr(attr int, buf []byte) *nl.RtAttr {
	return nl.NewRtAttr(attr, buf)
}

func (cl *NlClient) buildGenlh(cmd uint8, version uint8) *nl.Genlmsg {
	return &nl.Genlmsg{
		Command: cmd,
		Version: version,
	}
}

func (cl *NlClient) buildNlh(t uint16, flags uint32) *nl.NetlinkRequest {
	return &nl.NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  t,
			Flags: unix.NLM_F_REQUEST | uint16(flags),
		},
	}
}

func (cl *NlClient) writeFcMapReq(msg vr.VrFcMapReq) ([]byte, error) {
	if err := msg.Write(cl.Context, cl.Protocol); err != nil {
		return []byte{}, err
	}

	return cl.Tranport.Bytes(), nil
}

func (cl *NlClient) writeInfo(msg vr.VrInfoReq) ([]byte, error) {
	if err := msg.Write(cl.Context, cl.Protocol); err != nil {
		return []byte{}, err
	}

	return cl.Tranport.Bytes(), nil
}

func (cl *NlClient) writeMemStats(msg vr.VrMemStatsReq) ([]byte, error) {
	if err := msg.Write(cl.Context, cl.Protocol); err != nil {
		return []byte{}, err
	}

	return cl.Tranport.Bytes(), nil
}

func main() {
	cl, err := initClient()
	if err != nil {
		panic(err)
	}

	fc_map_req := vr.VrMemStatsReq{}
	fc_map_req.HOp = vr.SandeshOp_GET

	bytes, err := cl.writeMemStats(fc_map_req)
	if err != nil {
		panic(err)
	}
	fmt.Printf("bytes: %+v\n", bytes)

	nlreq := cl.buildNlh(cl.Family.ID, 0)
	nlreq.AddData(cl.buildGenlh(SANDESH_REQUEST, 0))
	nlreq.AddData(cl.buildNlAttr(NL_ATTR_VR_MESSAGE_PROTOCOL, bytes))

	msgs, err := nlreq.Execute(unix.NETLINK_GENERIC, 0)
	if err != nil {
		panic(err)
	}

	for _, m := range msgs {
		fmt.Printf("msgs: %+v\n", m)

		attrs, err := nl.ParseRouteAttr(m[nl.SizeofGenlmsg:])
		if err != nil {
			panic(err)
		}

		fmt.Printf("attrs: %+v\n", attrs)
	}
}
