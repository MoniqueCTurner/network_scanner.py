from scapy.all import ARP, Ether, srp
import ipaddress

def scan_network(network):
    # Create an ARP request packet
    arp = ARP(pdst=str(network))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and capture the response
    result = srp(packet, timeout=2, verbose=0)[0]

    # Process the results
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    # Define the network to scan
    network_input = input("Enter the network (e.g., 192.168.1.0/24): ")
    network = ipaddress.ip_network(network_input)

    devices = scan_network(network)
    
    print("Available devices in the network:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")
