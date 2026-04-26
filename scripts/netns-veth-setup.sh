#!/bin/bash
set -eo pipefail

NS="kwatch_test_ns"
VETH_HOST="veth_host"
VETH_NS="veth_ns"

setup() {
    ip netns add $NS
    ip link add $VETH_HOST type veth peer name $VETH_NS
    ip link set $VETH_NS netns $NS
    
    ip addr add 10.0.0.1/24 dev $VETH_HOST
    ip link set $VETH_HOST up
    
    ip netns exec $NS ip addr add 10.0.0.2/24 dev $VETH_NS
    ip netns exec $NS ip link set $VETH_NS up
    ip netns exec $NS ip link set lo up
}

cleanup() {
    ip link delete $VETH_HOST 2>/dev/null || true
    ip netns delete $NS 2>/dev/null || true
}

if [ "$1" == "setup" ]; then
    cleanup
    setup
elif [ "$1" == "cleanup" ]; then
    cleanup
else
    echo "Usage: $0 {setup|cleanup}"
    exit 1
fi
