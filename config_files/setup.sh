#!/bin/bash
sudo modprobe sheep_net
sudo chown pi /dev/sheep_net
sudo ip link add name br0 type bridge
sudo ip link set dev br0 promisc on
sudo ip link add maceth0 type veth peer name maceth1
sudo ip link add maceth2 type veth peer name maceth3
sudo ip link set maceth0 master br0
sudo ip link set maceth2 master br0
sudo ip link set maceth0 promisc on
sudo ip link set maceth1 promisc on
sudo ip link set maceth2 promisc on
sudo ip link set maceth3 promisc on
sudo ip link set dev br0 up
sudo ip link set maceth0 up
sudo ip link set maceth1 up
sudo ip link set maceth2 up
sudo ip link set maceth3 up
sleep 5
