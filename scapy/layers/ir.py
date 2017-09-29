## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
IrDA infrared data communication.
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import CookedLinux



# IR

class IrLAPHead(Packet):
    name = "IrDA Link Access Protocol Header"
    fields_desc = [ XBitField("address", 0x7f, 7),
                    BitEnumField("type", 1, 1, {"response":0,
                                                "cmd":1})]

class IrLAPCommand(Packet):
    name = "IrDA Link Access Protocol Command"
    fields_desc = [ XByteField("control", 0),
                    XByteField("format", 0),
                    XIntField("src", 0),
                    XIntField("dest", 0xffffffffL),
                    XByteField("discovery", 0x1),
                    ByteEnumField("slot", 255, {"final":255}),
                    XByteField("ver", 0)]


class IrLMP(Packet):
    name = "IrDA Link Management Protocol"
    fields_desc = [ XShortField("hints", 0),
                    XByteField("charset", 0),
                    StrField("device", "") ]


bind_layers( CookedLinux,   IrLAPHead,     proto=23)
bind_layers( IrLAPHead,     IrLAPCommand,  type=1)
bind_layers( IrLAPCommand,  IrLMP,         )
