## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
HSRP (Hot Standby Router Protocol): proprietary redundancy protocol for Cisco routers.
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP

hsrp_opcodes = { 0:"hello",
                 1:"coup",
                 2:"resign",
                 3:"advertise" }

hsrp_states = {  0:"initial",
                 1:"learn",
                 2:"listen",
                 4:"speak",
                 8:"standby",
                16:"active" }

class HSRP(Packet): # RFC 2281
    name = "HSRP"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 0, hsrp_opcodes),
        ByteEnumField("state", 16, hsrp_states),
        ByteField("hellotime", 3),
        ByteField("holdtime", 10),
        ByteField("priority", 120),
        ByteField("group", 1),
        ByteField("reserved", 0),
        StrFixedLenField("auth","cisco",8),
        IPField("virtualIP","192.168.1.1") ]
    overload_fields = {UDP: {"sport": 1985, "dport": 1985 }}

class HSRPAdvertisement(Packet): # undocumented
    name = "HSRP Advertisement"
    fields_desc = [
        ByteField("version", 0),
        ByteEnumField("opcode", 3, hsrp_opcodes),
        ShortEnumField("type", 1, {1:"if-state", 2:"ip-redundancy"}),
        FieldLenField("length", None, length_of="reserved2",
                      fmt="!H", adjust = lambda pkt,x: x+10),
        ByteEnumField("state", 2, {0:"dormant", 1:"passive", 2:"active"}),
        ByteField("reserved", 0),
        ShortField("activegroups", 0),
        ShortField("passivegroups", 1),
        StrLenField("reserved2", "", length_from = lambda pkt: pkt.length-10) ]
    overload_fields = {UDP: {"sport": 1985, "dport": 1985 }}

def _hsrp_dispatcher(x, *args, **kargs):
    cls = Raw
    if len(x) >= 2:
        if ord(x[0]) == 0 and ord(x[1]) == 3:
            cls = HSRPAdvertisement
        else:
            cls = HSRP
    try:
        pkt = cls(x, *args, **kargs)
    except:
        pkt = Raw(x)
    return pkt

bind_bottom_up(UDP, _hsrp_dispatcher, { "dport": 1985 })
bind_bottom_up(UDP, _hsrp_dispatcher, { "sport": 1985 })
