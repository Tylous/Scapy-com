## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

## Copyright (c) 2008  Dirk Loss <mail dirk-loss de>
## Copyright (c) 2010  Jochen Bartl <jochen.bartl gmail com>

"""
OSPF (Open Shortest Path First) Protocol.

This module provides Scapy layers for the Open Shortest Path First
routing protocol as defined in RFC 2328, 5340 and 5613.
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, IP6Field, in6_chksum


_OSPF_options = ["MT","E","MC","NP","L","DC","O","DN"]

_OSPF_types = {1: "Hello",
               2: "DBDesc",
               3: "LSReq",
               4: "LSUpd",
               5: "LSAck"}


class OSPF_Hdr(Packet):
    name = "OSPF Header"
    fields_desc = [
                    ByteField("version", 2),
                    ByteEnumField("type", 0, _OSPF_types),
                    ShortField("len", None),
                    IPField("src", "1.1.1.1"),
                    IPField("area", "0.0.0.0"),
                    XShortField("chksum", None),
                    ShortEnumField("authtype", 0, {0: "Null", 1: "Simple", 2: "Crypto"}),
                    # Null or Simple Authentication
                    ConditionalField(XLongField("authdata", 0), lambda pkt: pkt.authtype != 2),
                    # Crypto Authentication
                    ConditionalField(XShortField("reserved", 0), lambda pkt: pkt.authtype == 2),
                    ConditionalField(ByteField("keyid", 1), lambda pkt: pkt.authtype == 2),
                    ConditionalField(ByteField("authdatalen", 0), lambda pkt: pkt.authtype == 2),
                    ConditionalField(XIntField("seq", 0), lambda pkt: pkt.authtype == 2),
                    ]

    def post_build(self, p, pay):
        # LLS data blocks may be attached to OSPF Hello and DD packets.
        # The length of the LLS block is not included into the length of the OSPF packet.

        llslen = 0

        if (self.type == 1 or self.type == 2) and isinstance(self.lastlayer(), OSPF_LLS_Hdr):
            llslen = len(self.lastlayer())

        p += pay
        l = self.len

        if l is None:
            l = len(p) - llslen
            p = p[:2] + struct.pack("!H", l) + p[4:]

        if self.chksum is None:
            if self.authtype == 2:
                ck = 0   # Crypto, see RFC 2328, D.4.3
            else:
                # Checksum is calculated without authentication data
                # Algorithm is the same as in IP()
                ck = checksum(p[:16] + p[24:])
                p = p[:12] + chr(ck >> 8) + chr(ck & 0xff) + p[14:]

        return p

    def hashret(self):
        return struct.pack("H", self.area) + self.payload.hashret()

    def answers(self, other):
        if (isinstance(other, OSPF_Hdr) and
            self.area == other.area and
            self.type == 5):  # Only acknowledgements answer other packets
                return self.payload.answers(other.payload)
        return 0


class OSPF_Hello(Packet):
    name = "OSPF Hello"
    fields_desc = [IPField("mask", "255.255.255.0"),
                   ShortField("hellointerval", 10),
                   FlagsField("options", 0, 8, _OSPF_options),
                   ByteField("prio", 1),
                   IntField("deadinterval", 40),
                   IPField("router", "0.0.0.0"),
                   IPField("backup", "0.0.0.0"),
                   FieldListField("neighbors", [], IPField("", "0.0.0.0"), length_from=lambda pkt: (pkt.underlayer.len - 44))]

    def guess_payload_class(self, payload):
        # Check presence of LLS data block flag
        if self.options & 0x10:
            return OSPF_LLS_Hdr
        else:
            return Packet.guess_payload_class(self, payload)


class LLS_Generic_TLV(Packet):
    name = "LLS Generic"
    fields_desc = [ShortField("type", 1),
                   FieldLenField("len", None, fmt="H", length_of="val"),
                   StrLenField("val", "", length_from=lambda x: x.len)]

    def guess_payload_class(self, p):
        return Padding


_LLS_ext_options = ["LR","RS","I","F"]


class LLS_Extended_Options(LLS_Generic_TLV):
    name = "LLS Extended Options and Flags"
    fields_desc = [ShortField("type", 1),
                   ShortField("len", 4),
                   FlagsField("options", 0, 32, _LLS_ext_options)]


class LLS_Crypto_Auth(LLS_Generic_TLV):
    name = "LLS Cryptographic Authentication"
    fields_desc = [ShortField("type", 2),
                   FieldLenField("len", None, fmt="H", length_of="authdata",
                                 adjust = lambda pkt,x: x+4),
                   XIntField("sequence", 0),
                   StrLenField("authdata", "\x00" * 16, length_from=lambda x: x.len-4)]


_OSPF_LLSclasses = {1: "LLS_Extended_Options",
                    2: "LLS_Crypto_Auth"}


def _LLSGuessPacketClass(p=None, **kargs):
    """Guess the correct LLS class for a given packet"""

    if p is None:
        return LLS_Generic_TLV(**kargs)

    cls = Raw

    if len(p) >= 4:
        typ = struct.unpack("!H", p[0:2])[0]
        clsname = _OSPF_LLSclasses.get(typ, "LLS_Generic_TLV")
        cls = globals()[clsname]

    return cls(p, **kargs)


class OSPF_LLS_Hdr(Packet):
    name = "OSPF Link-local signaling"
    fields_desc = [XShortField("chksum", None),
                   ShortField("len", None), # Length in 32-bit words
                   PacketListField("llstlv", [], _LLSGuessPacketClass)]

    def post_build(self, p, pay):
        p += pay
        l = self.len
        if l is None:
            # Length in 32-bit words
            l = len(p) / 4
            p = p[:2] + struct.pack("!H", l) + p[4:]
        if self.chksum is None:
            c = checksum(p)
            p = chr((c >> 8) & 0xff) + chr(c & 0xff) + p[2:]
        return p

_OSPF_LStypes = {1: "router",
                 2: "network",
                 3: "summaryIP",
                 4: "summaryASBR",
                 5: "external",
                 7: "NSSAexternal"}

_OSPF_LSclasses = {1: "OSPF_Router_LSA",
                   2: "OSPF_Network_LSA",
                   3: "OSPF_SummaryIP_LSA",
                   4: "OSPF_SummaryASBR_LSA",
                   5: "OSPF_External_LSA",
                   7: "OSPF_NSSA_External_LSA"}


def ospf_lsa_checksum(lsa):
    """Fletcher checksum for OSPF LSAs, returned as a 2 byte string.

    Give the whole LSA packet as argument.
    For details on the algorithm, see RFC 2328 chapter 12.1.7 and RFC 905 Annex B.
    """
    # This is based on the GPLed C implementation in Zebra <http://www.zebra.org/>

    CHKSUM_OFFSET = 16

    if len(lsa) < CHKSUM_OFFSET:
        raise Exception("LSA Packet too short (%s bytes)" % len(lsa))

    c0 = c1 = 0
    # Calculation is done with checksum set to zero
    lsa = lsa[:CHKSUM_OFFSET] + "\x00\x00" + lsa[CHKSUM_OFFSET + 2:]
    for char in lsa[2:]:  #  leave out age
        c0 += ord(char)
        c1 += c0

    c0 %= 255
    c1 %= 255

    x = ((len(lsa) - CHKSUM_OFFSET - 1) * c0 - c1) % 255

    if (x <= 0):
        x += 255

    y = 510 - c0 - x

    if (y > 255):
        y -= 255

    return chr(x) + chr(y)


class _OSPF_BaseLSA(Packet):
    """An abstract base class for Link State Advertisements"""

    def post_build(self, p, pay):
        if self.len is None:
            length = len(p)
            p = p[:18] + struct.pack("!H", length) + p[20:]
        if self.chksum is None:
            chksum = ospf_lsa_checksum(p)
            p = p[:16] + chksum + p[18:]
        return p+pay

    def extract_padding(self, s):
        return "", s


class OSPF_LSA_Hdr(_OSPF_BaseLSA):
    name = "OSPF LSA Header"
    fields_desc = [ShortField("age", 1),
                   FlagsField("options", 0, 8, _OSPF_options),
                   ByteEnumField("type", 0, _OSPF_LStypes),
                   IPField("id", "192.168.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None)]


_OSPF_Router_LSA_types = {1: "p2p",
                          2: "transit",
                          3: "stub",
                          4: "virtual"}


class OSPF_Link(Packet):
    name = "OSPF Link"
    fields_desc = [IPField("id", "192.168.0.0"),
                   IPField("data", "255.255.255.0"),
                   ByteEnumField("type", 3, _OSPF_Router_LSA_types),
                   ByteField("toscount", 0),
                   ShortField("metric", 10)]

    def extract_padding(self, s):
        return "", s


def _LSAGuessPacketClass(p=None, **kargs):
    """Guess the correct LSA class for a given packet"""

    if p is None:
        return OSPF_LSA_Hdr(**kargs)

    cls = Raw

    if len(p) >= 4:
        typ = struct.unpack("!B", p[3])[0]
        clsname = _OSPF_LSclasses.get(typ, "OSPF_LSA_Hdr")
        cls = globals()[clsname]

    return cls(p, **kargs)


class OSPF_Router_LSA(_OSPF_BaseLSA):
    name = "OSPF Router LSA"
    type = 1
    id = "1.1.1.1"
    fields_desc = [OSPF_LSA_Hdr,
                   FlagsField("flags", 0, 8, ["B","E","V","W","Nt"]),
                   ByteField("reserved", 0),
                   FieldLenField("linkcount", None, count_of="linklist"),
                   PacketListField("linklist", [], OSPF_Link,
                                   count_from=lambda pkt: pkt.linkcount,
                                   length_from=lambda pkt: pkt.linkcount * 12)]


class OSPF_Network_LSA(_OSPF_BaseLSA):
    name = "OSPF Network LSA"
    type = 2
    fields_desc = [OSPF_LSA_Hdr,
                   IPField("mask", "255.255.255.0"),
                   FieldListField("routerlist", [], IPField("", "1.1.1.1"),
                                  length_from=lambda pkt: pkt.len - 24)]


class OSPF_SummaryIP_LSA(_OSPF_BaseLSA):
    name = "OSPF Summary LSA (IP Network)"
    type = 3
    fields_desc = [OSPF_LSA_Hdr,
                   IPField("mask", "255.255.255.0"),
                   ByteField("reserved", 0),
                   XThreeBytesField("metric", 10)]


class OSPF_SummaryASBR_LSA(OSPF_SummaryIP_LSA):
    name = "OSPF Summary LSA (AS Boundary Router)"
    type = 4
    id = "2.2.2.2"
    mask = "0.0.0.0"
    metric = 20


class OSPF_External_LSA(_OSPF_BaseLSA):
    name = "OSPF External LSA (ASBR)"
    type = 5
    adrouter = "2.2.2.2"
    fields_desc = [OSPF_LSA_Hdr,
                   IPField("mask", "255.255.255.0"),
                   FlagsField("ebit", 0, 1, ["E"]),
                   BitField("reserved", 0, 7),
                   XThreeBytesField("metric", 20),
                   IPField("fwdaddr", "0.0.0.0"),
                   XIntField("tag", 0)]


class OSPF_NSSA_External_LSA(OSPF_External_LSA):
    name = "OSPF NSSA External LSA"
    type = 7


class OSPF_DBDesc(Packet):
    name = "OSPF Database Description"
    fields_desc = [ShortField("mtu", 1500),
                   FlagsField("options", 0, 8, _OSPF_options),
                   FlagsField("dbdescr", 0, 8, ["MS","M","I","R","M6"]),
                   IntField("ddseq", 1),
                   PacketListField("lsaheaders", None, OSPF_LSA_Hdr,
                                    count_from = lambda pkt: None,
                                    length_from = lambda pkt: pkt.underlayer.len - 24 - 8)]

    def guess_payload_class(self, payload):
        # Check presence of LLS data block flag
        if self.options & 0x10:
            return OSPF_LLS_Hdr
        else:
            return Packet.guess_payload_class(self, payload)


class OSPF_LSReq_Item(Packet):
    name = "OSPF Link State Request (item)"
    fields_desc = [IntEnumField("type", 1, _OSPF_LStypes),
                   IPField("id", "1.1.1.1"),
                   IPField("adrouter", "1.1.1.1")]

    def extract_padding(self, s):
        return "", s


class OSPF_LSReq(Packet):
    name = "OSPF Link State Request (container)"
    fields_desc = [PacketListField("requests", None, OSPF_LSReq_Item,
                                  count_from = lambda pkt:None,
                                  length_from = lambda pkt:pkt.underlayer.len - 24)]


class OSPF_LSUpd(Packet):
    name = "OSPF Link State Update"
    fields_desc = [FieldLenField("lsacount", None, fmt="!I", count_of="lsalist"),
                   PacketListField("lsalist", [], _LSAGuessPacketClass,
                                count_from = lambda pkt: pkt.lsacount,
                                length_from = lambda pkt: pkt.underlayer.len - 24)]


class OSPF_LSAck(Packet):
    name = "OSPF Link State Acknowledgement"
    fields_desc = [PacketListField("lsaheaders", None, OSPF_LSA_Hdr,
                                   count_from = lambda pkt: None,
                                   length_from = lambda pkt: pkt.underlayer.len - 24)]

    def answers(self, other):
        if isinstance(other, OSPF_LSUpd):
            for reqLSA in other.lsalist:
                for ackLSA in self.lsaheaders:
                    if (reqLSA.type == ackLSA.type and
                        reqLSA.seq == ackLSA.seq):
                        return 1
        return 0


#------------------------------------------------------------------------------
# OSPFv3
#------------------------------------------------------------------------------
class OspfIP6Field(StrField, IP6Field):
    """Field for prefixes in OSPFv3 LSAs

    An address prefix is an even multiple of 32-bit words.
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
            warning("OspfIP6Field: Prefix length is > 128. Dissection of this packet will fail")
        else:
            pad = "\x00" * (16 - prefixlen)
            x += pad

        return inet_ntop(socket.AF_INET6, x)

    def prefixlen_to_bytelen(self, l):
        if l <= 32:
            return 4
        elif l <= 64:
            return 8
        elif l <= 96:
            return 12
        else:
            return 16

    def i2len(self, pkt, x):
        l = self.length_from(pkt)
        l = self.prefixlen_to_bytelen(l)

        return l

    def getfield(self, pkt, s):
        l = self.length_from(pkt)
        l = self.prefixlen_to_bytelen(l)

        return s[l:], self.m2i(pkt, s[:l])


class OSPFv3_Hdr(Packet):
    name = "OSPFv3 Header"
    fields_desc = [ByteField("version", 3),
                   ByteEnumField("type", 0, _OSPF_types),
                   ShortField("len", None),
                   IPField("src", "1.1.1.1"),
                   IPField("area", "0.0.0.0"),
                   XShortField("chksum", None),
                   ByteField("instance", 0),
                   ByteField("reserved", 0)]

    def post_build(self, p, pay):
        p += pay
        l = self.len

        if l is None:
            l = len(p)
            p = p[:2] + struct.pack("!H", l) + p[4:]

        if self.chksum is None:
            chksum = in6_chksum(89, self.underlayer, p)
            p = p[:12] + chr(chksum >> 8) + chr(chksum & 0xff) + p[14:]

        return p


_OSPFv3_options = ["V6","E","MC","N","R","DC","","",
                   "AF","L","I","F"]


class OSPFv3_Hello(Packet):
    name = "OSPFv3 Hello"
    fields_desc = [IntField("intid", 0),
                   ByteField("prio", 1),
                   FlagsField("options", 0, 24, _OSPFv3_options),
                   ShortField("hellointerval", 10),
                   ShortField("deadinterval", 40),
                   IPField("router", "0.0.0.0"),
                   IPField("backup", "0.0.0.0"),
                   FieldListField("neighbors", [], IPField("", "0.0.0.0"),
                                  length_from=lambda pkt: (pkt.underlayer.len - 36))]


_OSPFv3_LStypes = {0x2001: "router",
                   0x2002: "network",
                   0x2003: "interAreaPrefix",
                   0x2004: "interAreaRouter",
                   0x4005: "asExternal",
                   0x2007: "type7",
                   0x0008: "link",
                   0x2009: "intraAreaPrefix"}

_OSPFv3_LSclasses = {0x2001: "OSPFv3_Router_LSA",
                     0x2002: "OSPFv3_Network_LSA",
                     0x2003: "OSPFv3_Inter_Area_Prefix_LSA",
                     0x2004: "OSPFv3_Inter_Area_Router_LSA",
                     0x4005: "OSPFv3_AS_External_LSA",
                     0x2007: "OSPFv3_Type_7_LSA",
                     0x0008: "OSPFv3_Link_LSA",
                     0x2009: "OSPFv3_Intra_Area_Prefix_LSA"}


class OSPFv3_LSA_Hdr(_OSPF_BaseLSA):
    name = "OSPFv3 LSA Header"
    fields_desc = [ShortField("age", 1),
                   ShortEnumField("type", 0, _OSPFv3_LStypes),
                   IPField("id", "0.0.0.0"),
                   IPField("adrouter", "1.1.1.1"),
                   XIntField("seq", 0x80000001),
                   XShortField("chksum", None),
                   ShortField("len", None)]


def _OSPFv3_LSAGuessPacketClass(p=None, **kargs):
    """ Guess the correct OSPFv3 LSA class for a given packet """

    if p is None:
        return OSPFv3_LSA_Hdr(**kargs)

    cls = Raw

    if len(p) >= 6:
        typ = struct.unpack("!H", p[2:4])[0]
        clsname = _OSPFv3_LSclasses.get(typ, "OSPFv3_LSA_Hdr")
        cls = globals()[clsname]

    return cls(p, **kargs)


_OSPFv3_Router_LSA_types = {1: "p2p",
                            2: "transit",
                            3: "reserved",
                            4: "virtual"}


class OSPFv3_Link(Packet):
    name = "OSPFv3 Link"
    fields_desc = [ByteEnumField("type", 1, _OSPFv3_Router_LSA_types),
                   FlagsField("ldoptions", 0, 8, ["U"]),
                   ShortField("metric", 10),
                   IntField("intid", 0),
                   IntField("neighintid", 0),
                   IPField("neighbor", "2.2.2.2")]

    def extract_padding(self, s):
        return "", s


class OSPFv3_Router_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 Router LSA"
    type = 0x2001
    fields_desc = [OSPFv3_LSA_Hdr,
                   FlagsField("flags", 0, 8, ["B","E","V","W","Nt"]),
                   FlagsField("options", 0, 24, _OSPFv3_options),
                   PacketListField("linklist", [], OSPFv3_Link,
                                   length_from=lambda pkt:pkt.len - 24)]


class OSPFv3_Network_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 Network LSA"
    type = 0x2002
    fields_desc = [OSPFv3_LSA_Hdr,
                   ByteField("reserved", 0),
                   FlagsField("options", 0, 24, _OSPFv3_options),
                   FieldListField("routerlist", [], IPField("", "0.0.0.1"),
                                  length_from=lambda pkt: pkt.len - 24)]


_OSPFv3_prefix_options = ["NU","LA","MC","P","DN"]


class OSPFv3_Inter_Area_Prefix_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 Inter Area Prefix LSA"
    type = 0x2003
    fields_desc = [OSPFv3_LSA_Hdr,
                   ByteField("reserved", 0),
                   XThreeBytesField("metric", 10),
                   ByteField("prefixlen", 64),
                   FlagsField("prefixoptions", 0, 8, _OSPFv3_prefix_options),
                   ShortField("reserved2", 0),
                   OspfIP6Field("prefix", "2001:db8:0:42::",
                                length_from=lambda pkt: pkt.prefixlen)]


class OSPFv3_Inter_Area_Router_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 Inter Area Router LSA"
    type = 0x2004
    fields_desc = [OSPFv3_LSA_Hdr,
                   ByteField("reserved", 0),
                   XThreeBytesField("metric", 1),
                   IPField("router", "2.2.2.2")]


class OSPFv3_AS_External_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 AS External LSA"
    type = 0x4005
    fields_desc = [OSPFv3_LSA_Hdr,
                   FlagsField("flags", 0, 8, ["T","F","E"]),
                   XThreeBytesField("metric", 20),
                   ByteField("prefixlen", 64),
                   FlagsField("prefixoptions", 0, 8, _OSPFv3_prefix_options),
                   ShortEnumField("reflstype", 0, _OSPFv3_LStypes),
                   OspfIP6Field("prefix", "2001:db8:0:42::",
                                length_from=lambda pkt: pkt.prefixlen),
                   ConditionalField(IP6Field("fwaddr", "::"),
                                    lambda pkt: pkt.flags & 0x02),
                   ConditionalField(IntField("tag", 0),
                                    lambda pkt: pkt.flags & 0x01),
                   ConditionalField(IPField("reflsid", 0),
                                    lambda pkt: pkt.reflstype != 0)]


class OSPFv3_Type_7_LSA(OSPFv3_AS_External_LSA):
    name = "OSPFv3 Type 7 LSA"
    type = 0x2007


class OSPFv3_Prefix_Item(Packet):
    name = "OSPFv3 Link Prefix Item"
    fields_desc = [ByteField("prefixlen", 64),
                   FlagsField("prefixoptions", 0, 8, _OSPFv3_prefix_options),
                   ShortField("metric", 10),
                   OspfIP6Field("prefix", "2001:db8:0:42::",
                                length_from=lambda pkt: pkt.prefixlen)]

    def extract_padding(self, s):
        return "", s


class OSPFv3_Link_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 Link LSA"
    type = 0x0008
    fields_desc = [OSPFv3_LSA_Hdr,
                   ByteField("prio", 1),
                   FlagsField("options", 0, 24, _OSPFv3_options),
                   IP6Field("lladdr", "fe80::"),
                   IntField("prefixes", 0),
                   PacketListField("prefixlist", None, OSPFv3_Prefix_Item,
                                  count_from = lambda pkt: pkt.prefixes)]


class OSPFv3_Intra_Area_Prefix_LSA(_OSPF_BaseLSA):
    name = "OSPFv3 Intra Area Prefix LSA"
    type = 0x2009
    fields_desc = [OSPFv3_LSA_Hdr,
                   ShortField("prefixes", 0),
                   ShortEnumField("reflstype", 0, _OSPFv3_LStypes),
                   IPField("reflsid", "0.0.0.0"),
                   IPField("refadrouter", "0.0.0.0"),
                   PacketListField("prefixlist", None, OSPFv3_Prefix_Item,
                                  count_from = lambda pkt: pkt.prefixes)]


class OSPFv3_DBDesc(Packet):
    name = "OSPFv3 Database Description"
    fields_desc = [ByteField("reserved", 0),
                   FlagsField("options", 0, 24, _OSPFv3_options),
                   ShortField("mtu", 1500),
                   ByteField("reserved2", 0),
                   FlagsField("dbdescr", 0, 8, ["MS","M","I","R","M6"]),
                   IntField("ddseq", 1),
                   PacketListField("lsaheaders", None, OSPFv3_LSA_Hdr,
                                    count_from = lambda pkt:None,
                                    length_from = lambda pkt:pkt.underlayer.len - 28)]


class OSPFv3_LSReq_Item(Packet):
    name = "OSPFv3 Link State Request (item)"
    fields_desc = [ShortField("reserved", 0),
                   ShortEnumField("type", 0x2001, _OSPFv3_LStypes),
                   IPField("id", "1.1.1.1"),
                   IPField("adrouter", "1.1.1.1")]

    def extract_padding(self, s):
        return "", s


class OSPFv3_LSReq(Packet):
    name = "OSPFv3 Link State Request (container)"
    fields_desc = [PacketListField("requests", None, OSPFv3_LSReq_Item,
                                  count_from = lambda pkt:None,
                                  length_from = lambda pkt:pkt.underlayer.len - 16)]


class OSPFv3_LSUpd(Packet):
    name = "OSPFv3 Link State Update"
    fields_desc = [FieldLenField("lsacount", None, fmt="!I", count_of="lsalist"),
                   PacketListField("lsalist", [], _OSPFv3_LSAGuessPacketClass,
                                count_from = lambda pkt:pkt.lsacount,
                                length_from = lambda pkt:pkt.underlayer.len - 16)]


class OSPFv3_LSAck(Packet):
    name = "OSPFv3 Link State Acknowledgement"
    fields_desc = [PacketListField("lsaheaders", None, OSPFv3_LSA_Hdr,
                                   count_from = lambda pkt:None,
                                   length_from = lambda pkt:pkt.underlayer.len - 16)]


bind_layers(IP, OSPF_Hdr, proto=89)
bind_layers(OSPF_Hdr, OSPF_Hello, type=1)
bind_layers(OSPF_Hdr, OSPF_DBDesc, type=2)
bind_layers(OSPF_Hdr, OSPF_LSReq, type=3)
bind_layers(OSPF_Hdr, OSPF_LSUpd, type=4)
bind_layers(OSPF_Hdr, OSPF_LSAck, type=5)

bind_layers(IPv6, OSPFv3_Hdr, nh=89)
bind_layers(OSPFv3_Hdr, OSPFv3_Hello, type=1)
bind_layers(OSPFv3_Hdr, OSPFv3_DBDesc, type=2)
bind_layers(OSPFv3_Hdr, OSPFv3_LSReq, type=3)
bind_layers(OSPFv3_Hdr, OSPFv3_LSUpd, type=4)
bind_layers(OSPFv3_Hdr, OSPFv3_LSAck, type=5)
