package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/mdlayher/genetlink"
	mnetlink "github.com/mdlayher/netlink"
	"github.com/shun159/vrftrace/gen-go/vr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const NL_ATTR_VR_MESSAGE_PROTOCOL = 1
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

func (cl *NlClient) writeVrfStatsReq(msg vr.VrVrfStatsReq) ([]byte, error) {
	if err := msg.Write(cl.Context, cl.Protocol); err != nil {
		return []byte{}, err
	}

	return cl.Tranport.Bytes(), nil
}

func (cl *NlClient) writeVrouterOps(msg vr.VrouterOps) ([]byte, error) {
	if err := msg.Write(cl.Context, cl.Protocol); err != nil {
		return []byte{}, err
	}

	return cl.Tranport.Bytes(), nil
}

func (cl *NlClient) writeVrInfo(msg vr.VrInfoReq) ([]byte, error) {
	if err := msg.Write(cl.Context, cl.Protocol); err != nil {
		return []byte{}, err
	}

	return cl.Tranport.Bytes(), nil
}

func (cl *NlClient) writeInterfaceReq(msg vr.VrInterfaceReq) ([]byte, error) {
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

	c, err := genetlink.Dial(nil)
	if err != nil {
		log.Fatalf("failed to dial generic netlink: %v", err)
	}
	defer c.Close()

	// Ask generic netlink if nl80211 is available.
	family, err := c.GetFamily(VROUTER_GENETLINK_FAMILY_NAME)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("%q family not available", "vrouter")
			return
		}

		log.Fatalf("failed to query for family: %v", VROUTER_GENETLINK_FAMILY_NAME)
	}

	vr_mem_stats_req := vr.VrMemStatsReq{}
	vr_mem_stats_req.HOp = vr.SandeshOp_GET

	sandesh_b, err := cl.writeMemStats(vr_mem_stats_req)
	if err != nil {
		panic(err)
	}

	b, err := mnetlink.MarshalAttributes([]mnetlink.Attribute{{
		Type: uint16(SANDESH_REQUEST),
		Data: sandesh_b,
	}})

	if err != nil {
		panic(err)
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			Command: NL_ATTR_VR_MESSAGE_PROTOCOL,
			Version: 0,
		},
		Data: b,
	}

	msgs, err := c.Execute(req, family.ID, mnetlink.Request)
	if err != nil {
		panic(err)
	}

	for _, m := range msgs {
		buf := bytes.NewBuffer(m.Data[4:])
		cl.Tranport.Buffer = buf
		vr_resp := vr.VrResponse{}
		err := vr_resp.Read(cl.Context, cl.Protocol)
		if err != nil {
			panic(err)
		}
		if vr_resp.RespCode == 0 {
			err := vr_mem_stats_req.Read(cl.Context, cl.Protocol)
			if err != nil {
				panic(err)
			}
			fmt.Printf("attrs: %+v\n", vr_mem_stats_req)
		}
	}
}
