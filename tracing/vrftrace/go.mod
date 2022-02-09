module github.com/shun159/vrftrace

go 1.15

require (
	github.com/apache/thrift v0.15.0
	github.com/aquasecurity/libbpfgo v0.2.3-libbpf-0.6.1
	github.com/mdlayher/genetlink v1.1.0 // indirect
	github.com/mdlayher/netlink v1.5.0 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
)

replace github.com/aquasecurity/libbpfgo v0.2.3-libbpf-0.6.1 => github.com/shun159/libbpfgo v0.2.4-libbpf-0.6.1.0.20220131051813-8ea14b8613e9
