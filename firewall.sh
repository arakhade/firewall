#!/bin/bash
# Script to be run on firewall

echo "ifconfig output"
ifconfig
echo "netstat -rn"
netstat -rn
echo "Enter the subnet of private network"
read subnet
echo "Enter the interface connected to switch"
read interface
echo "Enter the ip address of the switch"
read ip

route add -net $subnet netmask 255.255.255.0 gw $ip dev $interface

sysctl -w net.ipv4.ip_forward=1

echo "netstat -rn after addition of route"
netstat -rn
