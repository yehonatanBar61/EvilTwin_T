#!/bin/sh


#    ===============================
#    We took inspiration from: https://aaronjohn2.github.io/2018/12/23/captive-portal/
#    ===============================



# Disable and stop systemd-resolved service
systemctl disable systemd-resolved.service
systemctl stop systemd-resolved

# Stop NetworkManager service
service NetworkManager stop

# Kill any interfering processes on the wireless interface using airmon-ng
airmon-ng check kill


#    ===============================
#    configure interface to have an IP address of 10.0.0.1
#    The reason we use 10.0.0.1 is because this is the ip address that is used 
#    by the dnsmasq.conf and all the requests is configured to go to this IP.
#    Here, 255.255.255.0 address is the most common subnet mask used on computers
#    ===============================

ifconfig ${INTERFACE} up 10.0.0.1 netmask 255.255.255.0

#    ===============================
#    delete any IP table rules that might interfere
#    ===============================

iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain

#    ===============================
#    Redirect any request to the captive portal
#    ===============================

iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 80 -j DNAT  --to-destination 10.0.0.1:80
iptables -t nat -A PREROUTING  -i usb0 -p tcp --dport 443 -j DNAT  --to-destination 10.0.0.1:80

#    ===============================
#    Enable internet access use the usb0 interface
#    ===============================
 
iptables -A FORWARD --in-interface ${INTERFACE} -j ACCEPT
iptables -t nat -A POSTROUTING --out-interface usb0 -j MASQUERADE

#    ===============================
#    Initial wifi interface configuration (seems to fix problems)
#    ===============================

ip link set ${INTERFACE} down
ip addr flush dev ${INTERFACE}
ip link set ${INTERFACE} up
ip addr add 192.168.24.1/24 dev ${INTERFACE}

#    ===============================
#    Enable IP forwarding from one interface to another
#    ===============================

echo 1 > /proc/sys/net/ipv4/ip_forward
sleep 3

#    ===============================
#    Add a default gateway to the route table again
#    ===============================

route add default gw 10.0.0.1

#    ===============================
#    start DHCP server and DNS server
#    ===============================

dnsmasq -C build/dnsmasq.conf

#    ===============================
#    start hostapd and to begin broadcasting a signal
#    ===============================

hostapd build/hostapd.conf -B


