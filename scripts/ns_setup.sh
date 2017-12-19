#!/bin/bash

if [ $USER != "root" ] ; then
    echo "Restarting script with sudo..."
    sudo $0 ${*}
    exit
fi

# delete previous incarnations if they exist
ip link del dev veth_vpp1
ip link del dev veth_vpp2
ip netns del vpp1
ip netns del vpp2

#create namespaces
ip netns add vpp1
ip netns add vpp2

# create and configure 1st veth pair
ip link add name veth_vpp1 type veth peer name vpp1
ip link set dev vpp1 up
ip link set dev veth_vpp1 up netns vpp1

ip netns exec vpp1 \
  bash -c "
    ip link set dev lo up
    ip addr add 172.16.1.2/24 dev veth_vpp1
    ip route add 172.16.2.0/24 via 172.16.1.1
"

# create and configure 2st veth pair
ip link add name veth_vpp2 type veth peer name vpp2
ip link set dev vpp2 up
ip link set dev veth_vpp2 up netns vpp2

ip netns exec vpp2 \
  bash -c "
    ip link set dev lo up
    ip addr add 172.16.2.2/24 dev veth_vpp2
    ip route add 172.16.1.0/24 via 172.16.2.1
"
