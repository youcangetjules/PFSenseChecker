# jan/02/1970 03:00:00 by RouterOS 7.14.2
# software id = ABCD-1234
#
/interface bridge
add name=bridge-lan protocol-mode=rstp comment="Main LAN bridge"
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan comment="Uplink to ISP"
set [ find default-name=ether2 ] name=ether2 comment="LAN port"
set [ find default-name=ether3 ] name=ether3
set [ find default-name=ether4 ] name=ether4 disabled=yes comment="spare"
/interface vlan
add interface=bridge-lan name=vlan10-servers vlan-id=10 comment="Servers"
add interface=bridge-lan name=vlan20-guest vlan-id=20 comment="Guest"
/interface bonding
add name=bond1 slaves=ether5,ether6 mode=802.3ad comment="LAG to core switch"
/interface wireguard
add name=wg0 listen-port=51820 comment="Road warrior VPN"
/interface bridge port
add bridge=bridge-lan interface=ether2
add bridge=bridge-lan interface=ether3
/ip pool
add name=dhcp-lan ranges=192.168.88.10-192.168.88.254
/ip dhcp-server
add address-pool=dhcp-lan interface=bridge-lan name=lan-dhcp lease-time=10m
/ip dhcp-client
add interface=ether1-wan
/ip address
add address=192.168.88.1/24 interface=bridge-lan network=192.168.88.0
add address=10.10.10.1/24 interface=vlan10-servers
add address=10.20.20.1/24 interface=vlan20-guest
add address=172.16.0.1/30 interface=bond1
/ip dns
set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes
/ip firewall filter
add action=accept chain=input connection-state=established,related comment="accept established"
add action=accept chain=input in-interface=bridge-lan comment="accept LAN to router"
add action=drop chain=input comment="drop everything else"
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1-wan comment="LAN masquerade"
/ip route
add dst-address=0.0.0.0/0 gateway=192.0.2.1 comment="default route"
/system identity
set name=CoreRouter-01
/user
add name=admin group=full
add name=netops group=read
