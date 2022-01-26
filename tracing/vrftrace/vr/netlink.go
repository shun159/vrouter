package vr

import (
	"bytes"
	"context"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const NL_ATTR_VR_MESSAGE_PROTOCOL = 1
const SANDESH_REQUEST = 1
const VROUTER_GENETLINK_FAMILY_NAME = "vrouter"

// Sandesh mesages
type Sandesh interface {
	// For vr.sandesh functions
	Read(context.Context, thrift.TProtocol) error
	Write(context.Context, thrift.TProtocol) error
}

// vrouter netlink client
type Netlink struct {
	*genetlink.Conn
	*genetlink.Family
	Ctx       context.Context
	Protocol  *TSandeshProtocol
	Transport *thrift.TMemoryBuffer
}

// netlink stream
type NetlinkStream struct {
	Buffer *bytes.Buffer
	Error  *error
}

// Instantiate netlink
func InitNetlink() (*Netlink, error) {
	netlink := Netlink{}
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	family, err := conn.GetFamily(VROUTER_GENETLINK_FAMILY_NAME)
	if err != nil {
		return nil, err
	}

	netlink.Conn = conn
	netlink.Family = &family
	netlink.Ctx = context.Background()
	netlink.Transport = thrift.NewTMemoryBuffer()
	netlink.Protocol = NewTSandeshProtocolTransport(netlink.Transport)

	return &netlink, nil
}

func (nl *Netlink) SendAsync(s_req Sandesh) <-chan *NetlinkStream {
	stream := make(chan *NetlinkStream)
	nlstream := NetlinkStream{}

	go func() {
		if err := s_req.Write(nl.Ctx, nl.Protocol); err != nil {
			nlstream.Error = &err
			stream <- &nlstream
			return
		}

		s_req_b := nl.Transport.Bytes()
		nl_msg, err := buildNlMsg(s_req_b)
		if err != nil {
			nlstream.Error = &err
			stream <- &nlstream
			return
		}

		msgs, err := nl.Conn.Execute(*nl_msg, nl.Family.ID, netlink.Request)
		if err != nil {
			nlstream.Error = &err
			stream <- &nlstream
			return
		}

		if len(msgs[0].Data) < 4 {
			nlstream.Error = &err
			stream <- &nlstream
			return
		}

		b := msgs[0].Data[4:]
		nlstream.Buffer = bytes.NewBuffer(b)
		stream <- &nlstream
	}()
	nl.Transport.Reset()

	return stream
}

// private functions

func buildNlMsg(s_req []byte) (*genetlink.Message, error) {
	nl_attr, err := buildNlAttr(s_req)
	if err != nil {
		return nil, nil
	}

	return &genetlink.Message{
		Header: genetlink.Header{
			Command: NL_ATTR_VR_MESSAGE_PROTOCOL,
			Version: 0,
		},
		Data: nl_attr,
	}, nil
}

func buildNlAttr(s_req_bytes []byte) ([]byte, error) {
	return netlink.MarshalAttributes([]netlink.Attribute{{
		Type: uint16(SANDESH_REQUEST),
		Data: s_req_bytes,
	}})
}
