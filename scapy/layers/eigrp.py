## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## Copyright (c) 2008  Jochen Bartl <jochen.bartl gmail com>
##                     Dirk Loss <mail dirk-loss de>

"""
EIGRP (Enhanced Interior Gateway Routing Protocol)
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IP6Field


class _EIGRP_IPField(StrField, IPField):
    """
    This is a special field type for handling ip addresses of destination networks in internal and
    external route updates.

    EIGRP removes zeros from the host portion of the ip address if the netmask is 8, 16 or 24 bits.
    """

    def __init__(self, name, default, length=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
        if length is not None:
            self.length_from = lambda pkt, length = length: length

    def h2i(self, pkt, x):
        return IPField.h2i(self, pkt, x)

    def i2m(self, pkt, x):
        x = inet_aton(x)
        l = self.length_from(pkt)

        if l <= 8:
            return x[:1]
        elif l <= 16:
            return x[:2]
        elif l <= 24:
            return x[:3]
        else:
            return x

    def m2i(self, pkt, x):
        l = self.length_from(pkt)

        if l <= 8:
            x += "\x00\x00\x00"
        elif l <= 16:
            x += "\x00\x00"
        elif l <= 24:
            x += "\x00"

        return inet_ntoa(x)

    def prefixlen_to_bytelen(self, l):
        if l <= 8:
            l = 1
        elif l <= 16:
            l = 2
        elif l <= 24:
            l = 3
        else:
            l = 4

        return l

    def i2len(self, pkt, x):
        l = self.length_from(pkt)
        l = self.prefixlen_to_bytelen(l)

        return l

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        l = self.prefixlen_to_bytelen(l)

        return s[l:], self.m2i(pkt, s[:l])

    def randval(self):
        return IPField.randval(self)


class _EIGRP_IP6Field(StrField, IP6Field, _EIGRP_IPField):
    """
    This is a special field type for handling ip addresses of destination networks in internal and
    external route updates.
    """

    def __init__(self, name, default, length=None, length_from=None):
        StrField.__init__(self, name, default)
        self.length_from = length_from
        if length is not None:
            self.length_from = lambda pkt, length = length: length

    def any2i(self, pkt, x):
        return IP6Field.any2i(self, pkt, x)

    def i2repr(self, pkt, x):
        return IP6Field.i2repr(self, pkt, x)

    def h2i(self, pkt, x):
        return IP6Field.h2i(self, pkt, x)

    def i2m(self, pkt, x):
        x = inet_pton(socket.AF_INET6, x)
        l = self.length_from(pkt)
        l = self.prefixlen_to_bytelen(l)

        return x[:l]

    def m2i(self, pkt, x):
        l = self.length_from(pkt)

        prefixlen = self.prefixlen_to_bytelen(l)
        if l > 128:
            warning("_EIGRP_IP6Field: Prefix length is > 128. Dissection of this packet will fail")
        else:
            pad = "\x00" * (16 - prefixlen)
            x += pad

        return inet_ntop(socket.AF_INET6, x)

    def prefixlen_to_bytelen(self, l):
        l = l / 8

        if l < 16:
            l += 1

        return l

    def i2len(self, pkt, x):
        return _EIGRP_IPField.i2len(self, pkt, x)

    def getfield(self, pkt, s):
        return _EIGRP_IPField.getfield(self, pkt, s)


_EIGRP_tlv_cls = {0x0001: "EIGRPParam",
                  0x0002: "EIGRPAuthData",
                  0x0003: "EIGRPSeq",
                  0x0004: "EIGRPSwVer",
                  0x0005: "EIGRPNms",
                  0x0006: "EIGRPStub",
                  0x0102: "EIGRPIntRoute",
                  0x0103: "EIGRPExtRoute",
                  0x0402: "EIGRPv6IntRoute",
                  0x0403: "EIGRPv6ExtRoute"}


_EIGRP_tlv_types = {0x0001: "Parameters",
                    0x0002: "Authentication Data",
                    0x0003: "Sequence",
                    0x0004: "Software Version",
                    0x0005: "Next Multicast Sequence",
                    0x0006: "Stub Router",
                    0x0102: "IPv4 Internal Route",
                    0x0103: "IPv4 External Route",
                    0x0202: "AppleTalk Internal Route",
                    0x0203: "AppleTalk External Route",
                    0x0204: "AppleTalk Cable Configuration",
                    0x0302: "IPX Internal Route",
                    0x0303: "IPX External Route",
                    0x0402: "IPv6 Internal Route",
                    0x0403: "IPv6 External Route"}


class EIGRPGeneric(Packet):
    name = "EIGRP Generic TLV"
    fields_desc = [XShortEnumField("type", 0x0000, _EIGRP_tlv_types),
                   FieldLenField("len", None, "value", "!H", adjust=lambda pkt, x: x + 4),
                   StrLenField("value", "\x00", length_from=lambda pkt: pkt.len - 4)]

    def guess_payload_class(self, p):
        return Padding


class EIGRPParam(EIGRPGeneric):
    name = "EIGRP Parameters"
    fields_desc = [XShortEnumField("type", 0x0001, _EIGRP_tlv_types),
                   ShortField("len", 12),
                   # Bandwidth
                   ByteField("k1", 1),
                   # Load
                   ByteField("k2", 0),
                   # Delay
                   ByteField("k3", 1),
                   # Reliability
                   ByteField("k4", 0),
                   # MTU
                   ByteField("k5", 0),
                   ByteField("reserved", 0),
                   ShortField("holdtime", 15)]


class EIGRPAuthData(EIGRPGeneric):
    name = "EIGRP Authentication Data"
    fields_desc = [XShortEnumField("type", 0x0002, _EIGRP_tlv_types),
                   FieldLenField("len", None, "authdata", "!H", adjust=lambda pkt, x: x + 24),
                   ShortEnumField("authtype", 2, {2: "MD5"}),
                   ShortField("keysize", None),
                   IntField("keyid", 1),
                   StrFixedLenField("nullpad", "\x00" * 12, 12),
                   StrLenField("authdata", RandString(16), length_from=lambda pkt: pkt.keysize)]

    def post_build(self, p, pay):
        if self.keysize is None:
            keysize = len(self.authdata)
            p = p[:6] + chr((keysize >> 8) & 0xff) + chr(keysize & 0xff) + p[8:]

        return p+pay


class EIGRPSeq(EIGRPGeneric):
    name = "EIGRP Sequence"
    fields_desc = [XShortEnumField("type", 0x0003, _EIGRP_tlv_types),
                   ShortField("len", None),
                   ByteField("addrlen", 4),
                   ConditionalField(IPField("ipaddr", "192.168.0.1"), lambda pkt: pkt.addrlen == 4),
                   ConditionalField(IP6Field("ip6addr", "fe80::1"), lambda pkt: pkt.addrlen == 16)]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p)
            p = p[:2] + chr((l >> 8) & 0xff) + chr(l & 0xff) + p[4:]

        return p+pay


class _EIGRP_ShortVersionField(ShortField):

    def i2repr(self, pkt, x):
        try:
            minor = x & 0xff
            major = (x >> 8) & 0xff
        except TypeError:
            return "unknown"
        else:
            # We print a leading 'v' so that these values don't look like floats
            return "v%s.%s" % (major, minor)

    def h2i(self, pkt, x):
        """The field accepts string values like v12.1, v1.1 or integer values.
           String values have to start with a "v" followed by a floating point number.
           Valid numbers are between 0 and 255.
        """

        if type(x) is str and x.startswith("v") and len(x) <= 8:
            major = int(x.split(".")[0][1:])
            minor = int(x.split(".")[1])

            return (major << 8) | minor

        elif type(x) is int and x >= 0 and x <= 65535:
            return x
        else:
            if self.default != None:
                warning("set value to default. Format of %r is invalid" % x)
                return self.default
            else:
                raise Scapy_Exception("Format of value is invalid")

    def randval(self):
        return RandShort()


class EIGRPSwVer(EIGRPGeneric):
    name = "EIGRP Software Version"
    fields_desc = [XShortEnumField("type", 0x0004, _EIGRP_tlv_types),
                   ShortField("len", 8),
                   _EIGRP_ShortVersionField("ios", "v12.0"),
                   _EIGRP_ShortVersionField("eigrp", "v1.2")]


class EIGRPNms(EIGRPGeneric):
    name = "EIGRP Next Multicast Sequence"
    fields_desc = [XShortEnumField("type", 0x0005, _EIGRP_tlv_types),
                   ShortField("len", 8),
                   IntField("nms", 2)]


_EIGRP_STUB_FLAGS = ["connected", "static", "summary", "receive-only", "redistributed", "leak-map"]


class EIGRPStub(EIGRPGeneric):
    name = "EIGRP Stub Router"
    fields_desc = [XShortEnumField("type", 0x0006, _EIGRP_tlv_types),
                   ShortField("len", 6),
                   FlagsField("flags", 0x000d, 16, _EIGRP_STUB_FLAGS)]


# Delay 0xffffffff == Destination Unreachable
class EIGRPIntRoute(EIGRPGeneric):
    name = "EIGRP Internal Route"
    fields_desc = [XShortEnumField("type", 0x0102, _EIGRP_tlv_types),
                   FieldLenField("len", None, "dst", "!H", adjust=lambda pkt, x: x + 25),
                   IPField("nexthop", "192.168.0.1"),
                   IntField("delay", 128000),
                   IntField("bandwidth", 256),
                   ThreeBytesField("mtu", 1500),
                   ByteField("hopcount", 0),
                   ByteField("reliability", 255),
                   ByteField("load", 0),
                   XShortField("reserved", 0),
                   ByteField("prefixlen", 24),
                   _EIGRP_IPField("dst", "192.168.1.0", length_from=lambda pkt: pkt.prefixlen)]


_EIGRP_EXTERNAL_PROTOCOL_ID = {0x01: "IGRP",
                               0x02: "EIGRP",
                               0x03: "Static Route",
                               0x04: "RIP",
                               0x05: "Hello",
                               0x06: "OSPF",
                               0x07: "IS-IS",
                               0x08: "EGP",
                               0x09: "BGP",
                               0x0A: "IDRP",
                               0x0B: "Connected Link"}

_EIGRP_EXTROUTE_FLAGS = ["external", "candidate-default"]


class EIGRPExtRoute(EIGRPGeneric):
    name = "EIGRP External Route"
    fields_desc = [XShortEnumField("type", 0x0103, _EIGRP_tlv_types),
                   FieldLenField("len", None, "dst", "!H", adjust=lambda pkt, x: x + 45),
                   IPField("nexthop", "192.168.0.1"),
                   IPField("originrouter", "192.168.0.1"),
                   IntField("originasn", 0),
                   IntField("tag", 0),
                   IntField("externalmetric", 0),
                   ShortField("reserved", 0),
                   ByteEnumField("extprotocolid", 3, _EIGRP_EXTERNAL_PROTOCOL_ID),
                   FlagsField("flags", 0, 8, _EIGRP_EXTROUTE_FLAGS),
                   IntField("delay", 0),
                   IntField("bandwidth", 256),
                   ThreeBytesField("mtu", 1500),
                   ByteField("hopcount", 0),
                   ByteField("reliability", 255),
                   ByteField("load", 0),
                   XShortField("reserved2", 0),
                   ByteField("prefixlen", 24),
                   _EIGRP_IPField("dst", "192.168.1.0", length_from=lambda pkt: pkt.prefixlen)]


class EIGRPv6IntRoute(EIGRPGeneric):
    name = "EIGRP for IPv6 Internal Route"
    fields_desc = [XShortEnumField("type", 0x0402, _EIGRP_tlv_types),
                   FieldLenField("len", None, "dst", "!H", adjust=lambda pkt, x: x + 37),
                   IP6Field("nexthop", "::"),
                   IntField("delay", 128000),
                   IntField("bandwidth", 256000),
                   ThreeBytesField("mtu", 1500),
                   ByteField("hopcount", 1),
                   ByteField("reliability", 255),
                   ByteField("load", 0),
                   XShortField("reserved", 0),
                   ByteField("prefixlen", 16),
                   _EIGRP_IP6Field("dst", "2001::", length_from=lambda pkt: pkt.prefixlen)]


class EIGRPv6ExtRoute(EIGRPGeneric):
    name = "EIGRP for IPv6 External Route"
    fields_desc = [XShortEnumField("type", 0x0403, _EIGRP_tlv_types),
                   FieldLenField("len", None, "dst", "!H", adjust=lambda pkt, x: x + 57),
                   IP6Field("nexthop", "::"),
                   IPField("originrouter", "192.168.0.1"),
                   IntField("originasn", 0),
                   IntField("tag", 0),
                   IntField("externalmetric", 0),
                   ShortField("reserved", 0),
                   ByteEnumField("extprotocolid", 3, _EIGRP_EXTERNAL_PROTOCOL_ID),
                   FlagsField("flags", 1, 8, _EIGRP_EXTROUTE_FLAGS),
                   IntField("delay", 0),
                   IntField("bandwidth", 256000),
                   ThreeBytesField("mtu", 1500),
                   ByteField("hopcount", 1),
                   ByteField("reliability", 0),
                   ByteField("load", 1),
                   XShortField("reserved2", 0),
                   ByteField("prefixlen", 0),
                   _EIGRP_IP6Field("dst", "::", length_from=lambda pkt: pkt.prefixlen)]


def _EIGRPGuessPacketClass(p=None, **kargs):
    if p is None:
        return EIGRPGeneric(**kargs)

    cls = Raw

    if len(p) >= 2:
        t = struct.unpack("!H", p[:2])[0]
        clsname = _EIGRP_tlv_cls.get(t, "EIGRPGeneric")
        cls = globals()[clsname]

    return cls(p, **kargs)

_EIGRP_OPCODES = {1: "Update",
                  2: "Request",
                  3: "Query",
                  4: "Reply",
                  5: "Hello",
                  6: "IPX SAP",
                  10: "SIA Query",
                  11: "SIA Reply"}

_EIGRP_FLAGS = ["init", "cond-recv", "", "update"]


class EIGRP(Packet):
    name = "EIGRP"
    fields_desc = [ByteField("ver", 2),
                   ByteEnumField("opcode", 5, _EIGRP_OPCODES),
                   XShortField("chksum", None),
                   FlagsField("flags", 0, 32, _EIGRP_FLAGS),
                   IntField("seq", 0),
                   IntField("ack", 0),
                   IntField("asn", 100),
                   PacketListField("tlvlist", [], _EIGRPGuessPacketClass)]

    def post_build(self, p, pay):
        p += pay

        if self.chksum is None:
            c = checksum(p)
            p = p[:2] + chr((c >> 8) & 0xff) + chr(c & 0xff) + p[4:]

        return p

    def mysummary(self):
        summarystr = "EIGRP (AS=%EIGRP.asn% Opcode=%EIGRP.opcode%"

        if self.opcode == 5 and self.ack != 0:
            summarystr += " (ACK)"

        if self.flags != 0:
            summarystr += " Flags=%EIGRP.flags%"

        return self.sprintf(summarystr + ")")


bind_layers(IP, EIGRP, proto=88)
bind_layers(IPv6, EIGRP, nh=88)
