package main

import (
	"fmt"
	"os"

	"github.com/shun159/vrftrace/vr"
)

func main() {
	nl, err := vr.InitNetlink()
	if err != nil {
		os.Exit(1)
	}

	vhost_conf := vr.NewFabricVifConfig()
	vhost_conf.Idx = 2
	vhost_conf.Name = "veth1"
	vhost_conf.MacAddr = "0e:8d:29:51:91:c3"
	vhost, err := vr.NewFabricVif(vhost_conf)

	if err != nil {
		os.Exit(1)
	}

	s_req := vhost.VrInterfaceReq
	stream := nl.SendAsync(s_req, nil)

	resp := <-stream
	vr_resp := resp.Messages[0].(*vr.VrResponse)
	if vr_resp.RespCode != 0 {
		fmt.Printf("Operation error: %+v\n", vr_resp.RespCode)
	}
}
