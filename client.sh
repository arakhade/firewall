#!/bin/bash
# Script to be run on client

echo "ifconfig eth1 output"
ifconfig eth1
echo "netstat -rn"
netstat -rn
echo "Enter the subnet og private network"
read subnet
echo "Enter the interface connected to firewall"
read interface
echo "Enter the ip address of the firewall"
read ip
route add -net $subnet netmask 255.255.255.0 gw $ip dev $interface
echo "netstat -rn after addition of route"
netstat -rn
