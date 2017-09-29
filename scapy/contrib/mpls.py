# http://trac.secdev.org/scapy/ticket/31 

# scapy.contrib.description = MPLS
# scapy.contrib.status = loads

import struct
from scapy.packet import Packet,bind_layers
from scapy.fields import BitField,ByteField
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.config import conf

#
# Support L3 MPLS
#
conf.l3mpls=True

class MPLS(Packet):
    name = "MPLS"
    fields_desc =  [ BitField("label", 3, 20),
                     BitField("cos", 0, 3),
                     BitField("s", 1, 1),
                     ByteField("ttl", 0) ]
    def guess_payload_class(self, pay):
        if self.s == 0:
            return MPLS
        b = struct.unpack("B", pay[0])[0]
        if conf.l3mpls:
            if b & 0xF0 == 0x60:
                return IPv6
            if b & 0xF0 == 0x40:
                return IP
        return Ether


bind_layers(MPLS,  MPLS, s=0) # Adding another label clears the BOS field
bind_layers(Ether, MPLS, type=0x8847)
