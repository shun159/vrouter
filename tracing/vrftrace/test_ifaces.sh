#!/bin/sh

echo "1 1" > /sys/bus/netdevsim/new_device 2>/dev/null
ip link add dev pkt0  type dummy
ip link add dev fabric0 type veth peer name veth1
ip link add dev tap0 type veth peer name veth3

ip link set dev pkt0 up
ip link set dev fabric0 up
ip link set dev tap0 up
ip link set dev veth1 up
ip link set dev veth3 up
