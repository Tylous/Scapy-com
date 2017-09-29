## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## Copyright (C) 2006    Nicolas Bareil  <nicolas.bareil AT eads DOT net>
##                       Arnaud Ebalard  <arnaud.ebalard AT eads DOT net>
##                       EADS/CRC security team

"""
CDP (Cisco Discovery Protocol)
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import SNAP
from scapy.layers.inet import IP
from scapy.layers.inet6 import IP6Field


_CDP_tlv_cls = {0x0001: "CDPMsgDeviceID",
                0x0002: "CDPMsgAddr",
                0x0003: "CDPMsgPortID",
                0x0004: "CDPMsgCapabilities",
                0x0005: "CDPMsgSoftwareVersion",
                0x0006: "CDPMsgPlatform",
                0x0007: "CDPMsgIPPrefix",
                0x0008: "CDPMsgProtoHello",
                0x0009: "CDPMsgVTPMgmtDomain",
                0x000a: "CDPMsgNativeVLAN",
                0x000b: "CDPMsgDuplex",
                0x000e: "CDPMsgVoIPVLANReply",
                0x000f: "CDPMsgVoIPVLANQuery",
                0x0010: "CDPMsgPower",
                0x0011: "CDPMsgMTU",
                0x0012: "CDPMsgTrustBitmap",
                0x0013: "CDPMsgUntrustedPortCoS",
                0x0014: "CDPMsgSystemName",
                0x0015: "CDPMsgSystemOID",
                0x0016: "CDPMsgMgmtAddr",
                0x0017: "CDPMsgLocation",
                0x001a: "CDPPowerAvailable"}

_CDP_tlv_types = {0x0001: "Device ID",
                  0x0002: "Addresses",
                  0x0003: "Port ID",
                  0x0004: "Capabilities",
                  0x0005: "Software Version",
                  0x0006: "Platform",
                  0x0007: "IP Prefix",
                  0x0008: "Protocol Hello",
                  0x0009: "VTP Mangement Domain",
                  0x000a: "Native VLAN",
                  0x000b: "Duplex",
                  0x000e: "VoIP VLAN Reply",
                  0x000f: "VoIP VLAN Query",
                  0x0010: "Power",
                  0x0011: "MTU",
                  0x0012: "Trust Bitmap",
                  0x0013: "Untrusted Port CoS",
                  0x0014: "System Name",
                  0x0015: "System OID",
                  0x0016: "Management Address",
                  0x0017: "Location",
                  0x001a: "Power Available"}


class CDPMsgGeneric(Packet):
    name = "CDP Generic Message"
    fields_desc = [XShortEnumField("type", 0x0000, _CDP_tlv_types),
                   FieldLenField("len", None, "val", "!H", adjust=lambda pkt,x: x + 4),
                   StrLenField("val", "", length_from=lambda x: x.len - 4)]

    def guess_payload_class(self, p):
        return Padding


def _CDPGuessPacketClass(p=None, **kargs):
    if p is None:
        return CDPMsgGeneric(**kargs)

    cls = Raw
    if len(p) >= 2:
        t = struct.unpack("!H", p[:2])[0]
        clsname = _CDP_tlv_cls.get(t, "CDPMsgGeneric")
        cls = globals()[clsname]

    return cls(p, **kargs)


class CDPMsgDeviceID(CDPMsgGeneric):
    name = "Device ID"
    type = 0x0001


_CDP_addr_record_ptype = {0x01: "NLPID", 0x02: "802.2"}
_CDP_addrrecord_proto_ip = "\xcc"
_CDP_addrrecord_proto_ipv6 = "\xaa\xaa\x03\x00\x00\x00\x86\xdd"


class CDPAddrRecord(Packet):
    name = "CDP Address"
    fields_desc = [ByteEnumField("ptype", 0x01, _CDP_addr_record_ptype),
                   FieldLenField("plen", None, "proto", "B"),
                   StrLenField("proto", None, length_from=lambda x:x.plen),
                   FieldLenField("addrlen", None, "addr", "!H"),
                   StrLenField("addr", None, length_from=lambda x:x.addrlen)]

    def guess_payload_class(self, p):
        return Padding


class CDPAddrRecordIPv4(CDPAddrRecord):
    name = "CDP Address IPv4"
    fields_desc = [ByteEnumField("ptype", 0x01, _CDP_addr_record_ptype),
                   FieldLenField("plen", 1, "proto", "B"),
                   StrLenField("proto", _CDP_addrrecord_proto_ip, length_from=lambda x:x.plen),
                   ShortField("addrlen", 4),
                   IPField("addr", "192.168.0.1")]


class CDPAddrRecordIPv6(CDPAddrRecord):
    name = "CDP Address IPv6"
    fields_desc = [ByteEnumField("ptype", 0x02, _CDP_addr_record_ptype),
                   FieldLenField("plen", 8, "proto", "B"),
                   StrLenField("proto", _CDP_addrrecord_proto_ipv6, length_from=lambda x:x.plen),
                   ShortField("addrlen", 16),
                   IP6Field("addr", "fe80::1")]


def _CDPGuessAddrRecord(p=None, **kargs):
    if p is None:
        return CDPAddrRecord(**kargs)

    cls = Raw

    if len(p) >= 2:
        plen = struct.unpack("B", p[1])[0]
        proto = ''.join(struct.unpack("s" * plen, p[2:plen + 2])[0:plen])

        if proto == _CDP_addrrecord_proto_ip:
            clsname = "CDPAddrRecordIPv4"
        elif proto == _CDP_addrrecord_proto_ipv6:
            clsname = "CDPAddrRecordIPv6"
        else:
            clsname = "CDPAddrRecord"

        cls = globals()[clsname]

    return cls(p, **kargs)


class CDPMsgAddr(CDPMsgGeneric):
    name = "Addresses"
    fields_desc = [XShortEnumField("type", 0x0002, _CDP_tlv_types),
                   ShortField("len", None),
                   FieldLenField("naddr", None, count_of="addr", fmt="!I"),
                   PacketListField("addr", [], _CDPGuessAddrRecord, count_from=lambda x: x.naddr)]

    def post_build(self, pkt, pay):
        if self.len is None:
            l = 8 + len(self.addr) * 9
            pkt = pkt[:2] + struct.pack("!H", l) + pkt[4:]
        p = pkt + pay

        return p


class CDPMsgPortID(CDPMsgGeneric):
    name = "Port ID"
    fields_desc = [XShortEnumField("type", 0x0003, _CDP_tlv_types),
                   FieldLenField("len", None, "iface", "!H", adjust=lambda pkt,x: x + 4),
                   StrLenField("iface", "FastEthernet0/1", length_from=lambda x: x.len - 4)]


_CDP_capabilities = ["Router",
                     "TransparentBridge",
                     "SourceRouteBridge",
                     "Switch",
                     "Host",
                     "IGMPCapable",
                     "Repeater"] + map(lambda x: "Bit%d" % x, range(25, 0, -1))


class CDPMsgCapabilities(CDPMsgGeneric):
    name = "Capabilities"
    fields_desc = [XShortEnumField("type", 0x0004, _CDP_tlv_types),
                   ShortField("len", 8),
                   FlagsField("cap", 0, 32, _CDP_capabilities)]


class CDPMsgSoftwareVersion(CDPMsgGeneric):
    name = "Software Version"
    type = 0x0005


class CDPMsgPlatform(CDPMsgGeneric):
    name = "Platform"
    type = 0x0006


# ODR Routing
class CDPMsgIPPrefix(CDPMsgGeneric):
    name = "IP Prefix"
    type = 0x0007
    fields_desc = [XShortEnumField("type", 0x0007, _CDP_tlv_types),
                   ShortField("len", 8),
                   IPField("defaultgw", "192.168.0.1")]


class CDPMsgProtoHello(CDPMsgGeneric):
    name = "Protocol Hello"
    type = 0x0008


class CDPMsgVTPMgmtDomain(CDPMsgGeneric):
    name = "VTP Management Domain"
    type = 0x0009


class CDPMsgNativeVLAN(CDPMsgGeneric):
    name = "Native VLAN"
    fields_desc = [XShortEnumField("type", 0x000a, _CDP_tlv_types),
                   ShortField("len", 6),
                   ShortField("vlan", 1)]


class CDPMsgDuplex(CDPMsgGeneric):
    name = "Duplex"
    fields_desc = [XShortEnumField("type", 0x000b, _CDP_tlv_types),
                   ShortField("len", 5),
                   ByteEnumField("duplex", 0x00, {0x00: "Half", 0x01: "Full"})]


class CDPMsgVoIPVLANReply(CDPMsgGeneric):
    name = "VoIP VLAN Reply"
    fields_desc = [XShortEnumField("type", 0x000e, _CDP_tlv_types),
                   ShortField("len", 7),
                   ByteField("status", 1),
                   ShortField("vlan", 1)]


class CDPMsgVoIPVLANQuery(CDPMsgGeneric):
    name = "VoIP VLAN Query"
    type = 0x000f


class _CDPPowerField(ShortField):

    def i2repr(self, pkt, x):
        if x is None:
            x = 0
        return "%d mW" % x


class CDPMsgPower(CDPMsgGeneric):
    name = "Power"
    fields_desc = [XShortEnumField("type", 0x0010, _CDP_tlv_types),
                   ShortField("len", 6),
                   _CDPPowerField("power", 1337)]


class CDPMsgMTU(CDPMsgGeneric):
    name = "MTU"
    fields_desc = [XShortEnumField("type", 0x0011, _CDP_tlv_types),
                   ShortField("len", 6),
                   ShortField("mtu", 1500)]


class CDPMsgTrustBitmap(CDPMsgGeneric):
    name = "Trust Bitmap"
    type = 0x0012


class CDPMsgUntrustedPortCoS(CDPMsgGeneric):
    name = "Untrusted Port CoS"
    type = 0x0013


class CDPMsgSystemName(CDPMsgGeneric):
    name = "System Name"
    type = 0x0014


class CDPMsgSystemOID(CDPMsgGeneric):
    name = "System OID"
    type = 0x0015


class CDPMsgMgmtAddr(CDPMsgAddr):
    name = "Management Address"
    type = 0x0016


class CDPMsgLocation(CDPMsgGeneric):
    name = "Location"
    type = 0x0017


class CDPPowerAvailable(CDPMsgGeneric):
    name = "Power Available"
    type = 0x001a


class CDPv2_Hdr(CDPMsgGeneric):
    name = "Cisco Discovery Protocol version 2"
    fields_desc = [ByteField("vers", 2),
                   ByteField("ttl", 180),
                   XShortField("cksum", None),
                   PacketListField("msg", [], _CDPGuessPacketClass)]

    def post_build(self, pkt, pay):
        p = pkt + pay

        if self.cksum is None:
            if len(p) % 2 == 0:
                cksum = checksum(p)
            else:
                cksum = checksum(p[0:-1] + "\x00" + p[-1])

            p = p[:2] + struct.pack("!H", cksum) + p[4:]

        return p


bind_layers(SNAP, CDPv2_Hdr, {"code": 0x2000, "OUI": 0xC})
