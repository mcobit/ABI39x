#!/bin/bash
sudo killall -9 BasiliskII
sudo killall -9 python3
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
x0vncserver -display :0 -localhost -SecurityTypes None
cd /home/pi
DISPLAY=:0.0 BasiliskII --sdlrender software &
sleep 10
cd /home/pi/status
sudo python3 status.py -i maceth1 &
sudo python3 /home/pi/tashtalkd_ethernet/tashtalkd/tashtalkd -d /dev/ttyS0 -i maceth3 &
sleep 5
cd /home/pi/noVNC-1.6.0/utils
sudo ./novnc_proxy --vnc localhost:5900 &
cd /home/pi
while [ $(pgrep BasiliskII) ]
do
  sleep 1
done
/bin/bash /home/pi/basilisk.sh
