## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Classes and functions for layer 2 protocols.
"""

import os,struct,time
from scapy.base_classes import Net
from scapy.config import conf
from scapy.packet import *
from scapy.ansmachine import *
from scapy.plist import SndRcvList
from scapy.fields import *
from scapy.sendrecv import srp,srp1,srpflood
from scapy.arch import LOOPBACK_NAME,get_if_hwaddr,pcapdnet




#################
## Tools       ##
#################


class Neighbor:
    def __init__(self):
        self.resolvers = {}

    def register_l3(self, l2, l3, resolve_method):
        self.resolvers[l2,l3]=resolve_method

    def resolve(self, l2inst, l3inst):
        k = l2inst.__class__,l3inst.__class__
        if k in self.resolvers:
            return self.resolvers[k](l2inst,l3inst)

    def __repr__(self):
        return "\n".join("%-15s -> %-15s" % (l2.__name__, l3.__name__) for l2,l3 in self.resolvers)

conf.neighbor = Neighbor()

conf.netcache.new_cache("arp_cache", 120) # cache entries expire after 120s


@conf.commands.register
def getmacbyip(ip, chainCC=0):
    """Return MAC address corresponding to a given IP address"""
    if type(ip) in (list,tuple):
        ip = ip[0]
    if isinstance(ip, VolatileValue):
        ip = str(ip)
    elif isinstance(ip, Net):
        ip = iter(ip).next()
    tmp = map(ord, inet_aton(ip))
    if (tmp[0] & 0xf0) == 0xe0: # mcast @
        return "01:00:5e:%.2x:%.2x:%.2x" % (tmp[1]&0x7f,tmp[2],tmp[3])
    iff,a,gw = conf.route.route(ip)
    if ( (iff == LOOPBACK_NAME) or (ip == conf.route.get_if_bcast(iff)) ):
        return "ff:ff:ff:ff:ff:ff"
    if WINDOWS:
        # Windows uses local IP instead of 0.0.0.0 to represent locally reachable addresses
        ifip = str(pcapdnet.dnet.intf().get(iff)['addr'])
        if gw != ifip.split('/')[0]:
            ip = gw
    else:
        if gw != "0.0.0.0":
            ip = gw

    mac = conf.netcache.arp_cache.get(ip)
    if mac:
        return mac

    res = srp1(Ether(dst=ETHER_BROADCAST)/ARP(op="who-has", pdst=ip),
               type=ETH_P_ARP,
               iface = iff,
               timeout=2,
               verbose=0,
               chainCC=chainCC,
               nofilter=1)
    if res is not None:
        mac = res.payload.hwsrc
        conf.netcache.arp_cache[ip] = mac
        return mac
    return None

#
# VLAN (and potentially) other tags.
#
# TPIDs (Tag Protocol IDs) are special ethertypes that signify TAGs, rather
# than real protocols. 
#
conf.inner_tpids = set([0x8100])
conf.outer_tpids = set([0x8100, 0x88a8, 0x9100, 0x9200])
conf.vntag_tpids = set([0x8926])
conf.tpids = conf.inner_tpids | conf.outer_tpids

conf.default_vlan=1
conf.default_src_mac="00:00:00:00:00:00"

#
# Useful Constants
#
ETHER_NONE       = -1
ETHER_LEN        = 0
ETHER_TYPE       = 1
ETHER_TPID       = 2
ETHER_INNER_TPID = 3
ETHER_OUTER_TPID = 4
ETHER_VNTAG      = 5
#
# Ethernet tag helper functions
#
def ether_short_get(s):
    """
    Interpret the first two bytes of a string as a short integer.
    If there is not enough data, return 0.
    """
    if len(s) >= 2:
        return struct.unpack("!H", s[0:2])[0]
    else:
        return 0

def ether_whatis(tpid_type_len):
    """
    Interpret a short (two bytes) as either a TPID,  Ethertype or length
    Returns the defined ENUM plus the length of the tag (or 0 if it is not a TPID)
    """
    if tpid_type_len <= 0x600:
        return (ETHER_LEN, 0)
    elif tpid_type_len in conf.tpids:
        return (ETHER_TPID, 4)
    elif tpid_type_len in conf.vntag_tpids:
        return (ETHER_TPID, 6)
    else:
        return (ETHER_TYPE, 0)

def ether_whatis2(tpid_type_len, s):
    """
    Interpret a short (two bytes) either as TPID, Ethertype or length,
    but distinguish between Inner and outer TPIDS, based on the
    bytes that follow the tag
    """
    (whatis, tag_len) = ether_whatis(tpid_type_len)
    if whatis == ETHER_TPID:
        if tpid_type_len in conf.vntag_tpids:
            return (ETHER_VNTAG, 6)
        
        outer = tpid_type_len in conf.outer_tpids
        inner = tpid_type_len in conf.inner_tpids
        if inner and outer:
            next_tpid_type_len = ether_short_get(s[tag_len:])
            if next_tpid_type_len in conf.tpids:
                inner = False

        if inner:
            return (ETHER_INNER_TPID, 4)
        if outer:
            return (ETHER_OUTER_TPID, 4)
    return (whatis, tag_len)
        
def EtherTag_dispatch_hook(cls, _pkt=None, *args, **kargs):
    """
    The function determines the class for a tag, based on the first two bytes (TPID)
    """
    if _pkt and len(_pkt) >=2:
        tpid_type_len = ether_short_get(_pkt)
        whatis = ether_whatis2(tpid_type_len, _pkt)[0]
        if whatis == ETHER_INNER_TPID:
            return Dot1Q
        elif whatis == ETHER_OUTER_TPID:
            return Dot1AD
        elif whatis == ETHER_VNTAG:
            return VNTag
        else:
            return Untagged
    return cls

def Ether_dispatch_hook(cls, _pkt=None, *args, **kargs):
    """
    The function determines the Ethernet encapsulation based on the type/len field.
    The trick is to get to that field by going past all the tags
    """
    if _pkt and len(_pkt) >= 14:
        offset = 12
        # Skip all the tags
        while offset <= len(_pkt) - 2:
            tag_type_len = ether_short_get(_pkt[offset:])
            (whatis, tag_len) = ether_whatis(tag_type_len)
            if whatis != ETHER_TPID:
                break
            offset += tag_len

        if whatis == ETHER_TYPE:
            return Ether
        if whatis == ETHER_LEN:
            return Dot3 
    return cls

#
# Ethernet Tags
#
class EtherTag(Packet):
    """
    Base Class for the Ethernet Tags
    """
    def guess_payload_class(self, s):
        if s is None:
            return Untagged

        next_whatis = ether_whatis2(ether_short_get(s), s)[0]
        if  next_whatis == ETHER_OUTER_TPID:
            return Dot1Q
        elif next_whatis == ETHER_INNER_TPID:
            return Dot1AD
        elif next_whatis == ETHER_VNTAG:
            return VNTag
        else:
            return Packet.guess_payload_class(self, s)
        
    def extract_padding(self, _pkt):
        tags_end = 0
        while tags_end < len(_pkt):
            (whatis, tag_len) = ether_whatis(ether_short_get(_pkt[tags_end:]))
            if whatis == ETHER_TPID: 
                tags_end += tag_len
                continue
            else:
                break
        return _pkt[:tags_end], _pkt[tags_end:]
    
    def answers(self, other):
        if self.vlan == conf.default_vlan or self.vlan == 0:
            if isinstance(other, Untagged) or other is None:
                return True
        if isinstance(other, EtherTag):
            if ( (self.tpid == other.tpid) and
                 (self.vlan == other.vlan) ):
                return self.payload.answers(other.payload)
            else:
                return False
    def mysummary(self):
        return self.sprintf("VID:%vlan%")

class Untagged(EtherTag):
    name = "Untagged"
    def answers(self, other):
        if other is None:
            return True
        if isinstance(other, Untagged):
            return True
        if (isinstance(other, EtherTag) and
            (other.vlan == 0) or (other.vlan == conf.default_vlan)):
            return True
        return False
    def mysummary(self):
        return self.printf("Untagged")
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return EtherTag_dispatch_hook(cls, _pkt, args, kargs)
 
class Dot1Q(EtherTag):
    name = "802.1Q"
    fields_desc =  [ XShortField("tpid", 0x8100),
                     BitField("prio", 0, 3),
                     BitField("cfi", 0, 1),
                     BitField("vlan", conf.default_vlan, 12)]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return EtherTag_dispatch_hook(cls, _pkt, args, kargs)

class Dot1AD(EtherTag):
    name = "802.1ad"
    fields_desc =  [ XShortField("tpid", 0x9100),
                     BitField("prio", 0, 3),
                     BitField("dei", 0, 1),
                     BitField("vlan", conf.default_vlan, 12)]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return EtherTag_dispatch_hook(cls, _pkt, args, kargs)

class VNTag(EtherTag):
    name = "VNTag"
    fields_desc =  [ XShortField("tpid", 0x8926),
                     BitField("dir",     0, 1),
                     BitField("ptr",     0, 1),
                     BitField("dst",     0, 14),
                     BitField("looped",  0, 1),
                     BitField("r",       0, 1),
                     BitField("version", 0, 2),
                     BitField("src",     0, 12) ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return EtherTag_dispatch_hook(cls, _pkt, args, kargs)

bind_layers(Dot1Q, Dot1Q, tpid=0x9100)
bind_layers(VNTag, Dot1Q, )

### Fields

class DestMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            x = conf.neighbor.resolve(pkt,pkt.payload)
            if x is None:
                x = "ff:ff:ff:ff:ff:ff"
                warning("Mac address to reach destination not found. Using broadcast.")
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        
class SourceMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            iff,a,gw = pkt.payload.route()
            if iff:
                try:
                    x = get_if_hwaddr(iff)
                except:
                    pass
            if x is None:
                x = conf.default_src_mac
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))
        
class ARPSourceMACField(MACField):
    def __init__(self, name):
        MACField.__init__(self, name, None)
    def i2h(self, pkt, x):
        if x is None:
            iff,a,gw = pkt.route()
            if iff:
                try:
                    x = get_if_hwaddr(iff)
                except:
                    pass
            if x is None:
                x = conf.default_src_mac
        return MACField.i2h(self, pkt, x)
    def i2m(self, pkt, x):
        return MACField.i2m(self, pkt, self.i2h(pkt, x))

### Layers

class Ethernet_base(Packet):
    """
    This is the base class for both types of Ethernet frames.
    This class overrides the standard __div__ method for the packets, so that if
    an ethernet packet is followed by a tag, it gets incorporated inside the "tags"
    field
    """
    def __div__(self, other):
        if isinstance(other, EtherTag) and isinstance(self.payload, NoPayload):
            cloneA = self.copy()
            cloneB = other.copy()
            payloadB = cloneB.payload
            cloneB.remove_payload()
            if cloneA.tags is None or isinstance(cloneA.tags, Untagged):
                cloneA.tags = cloneB
            else:
                cloneA.tags /= cloneB
            return cloneA/payloadB
        else:
            return Packet.__div__(self, other)

class Ether(Ethernet_base):
    name = "Ethernet"
    fields_desc = [ DestMACField("dst"),
                    SourceMACField("src"),
                    PacketField("tags", Untagged(), Dot1Q),
                    XShortEnumField("type", 0x0600, ETHER_TYPES) ]
    def hashret(self):
        return struct.pack("H",self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,Ether):
            if self.type == other.type:
                if ((self.tags is None and other.tags is None) or
                    (self.tags is None and isinstance(other.tags, Untagged)) or
                    (self.tags is not None and self.tags.answers(other.tags))):
                    return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        if self.tags is None:
            return self.sprintf("%src% > %dst% Untagged (%type%)")
        else:
            return self.sprintf("%src% > %dst% ") + \
                   self.tags.mysummary()          + \
                   self.sprintf(" (%type%)")
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return Ether_dispatch_hook(cls, _pkt, args, kargs)

class Dot3(Ethernet_base):
    name = "802.3"
    fields_desc = [ DestMACField("dst"),
                    MACField("src", ETHER_ANY),
                    PacketField("tags", Untagged(), Dot1Q),
                    LenField("len", None, "H") ]
    def extract_padding(self,s):
        l = self.len
        return s[:l],s[l:]
    def answers(self, other):
        if isinstance(other,Dot3):
            if ((self.tags is None and other.tags is None) or
                ((self.tags is not None and other.tags is not None) and
                 self.tags.answers(other.tags))):
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return "802.3 %s > %s" % (self.src, self.dst)
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return Ether_dispatch_hook(cls, _pkt, args, kargs)


class LLC(Packet):
    name = "LLC"
    fields_desc = [ XByteField("dsap", 0x00),
                    XByteField("ssap", 0x00),
                    ByteField("ctrl", 0) ]

conf.neighbor.register_l3(Ether, LLC, lambda l2,l3: conf.neighbor.resolve(l2,l3.payload))
conf.neighbor.register_l3(Dot3, LLC, lambda l2,l3: conf.neighbor.resolve(l2,l3.payload))


class CookedLinux(Packet):
    name = "cooked linux"
    fields_desc = [ ShortEnumField("pkttype",0, {0: "unicast",
                                                 4:"sent-by-us"}), #XXX incomplete
                    XShortField("lladdrtype",512),
                    ShortField("lladdrlen",0),
                    StrFixedLenField("src","",8),
                    XShortEnumField("proto",0x800,ETHER_TYPES) ]
                    
                                   

class SNAP(Packet):
    name = "SNAP"
    fields_desc = [ XThreeBytesField("OUI",0x000000),
                    XShortEnumField("code", 0x000, ETHER_TYPES) ]

conf.neighbor.register_l3(Dot3, SNAP, lambda l2,l3: conf.neighbor.resolve(l2,l3.payload))

    
conf.neighbor.register_l3(Ether, Dot1Q, lambda l2,l3: conf.neighbor.resolve(l2,l3.payload))

class STP(Packet):
    name = "Spanning Tree Protocol"
    fields_desc = [ ShortField("proto", 0),
                    ByteField("version", 0),
                    ByteField("bpdutype", 0),
                    ByteField("bpduflags", 0),
                    ShortField("rootid", 0),
                    MACField("rootmac", ETHER_ANY),
                    IntField("pathcost", 0),
                    ShortField("bridgeid", 0),
                    MACField("bridgemac", ETHER_ANY),
                    ShortField("portid", 0),
                    BCDFloatField("age", 1),
                    BCDFloatField("maxage", 20),
                    BCDFloatField("hellotime", 2),
                    BCDFloatField("fwddelay", 15) ]


eap_types = {	1:"ID",
				2:"NOTIFICATION",
				3:"LEGACY NAK",
				4:"MD5",
				5:"ONE TIME PASSWORD",
				6:"GENERIC TOKEN CARD",
				13:"EAP-TLS",
				17:"LEAP",
				21:"EAP-TTLS",
				25:"PEAP",
				43:"EAP-FAST",
				254:"EXPANDED EAP"
			}

class EAPOL(Packet):
    name = "EAPOL"
    fields_desc = [ ByteField("version", 1),
                    ByteEnumField("type", 0, ["EAP_PACKET", "START", "LOGOFF", "KEY", "ASF"]),
                    LenField("len", None, "H") ]
    
    EAP_PACKET= 0
    START = 1
    LOGOFF = 2
    KEY = 3
    ASF = 4
    def extract_padding(self, s):
        l = self.len
        return s[:l],s[l:]
    def hashret(self):
        return chr(self.type)+self.payload.hashret()
    def answers(self, other):
        if isinstance(other,EAPOL):
            if ( (self.type == self.EAP_PACKET) and
                 (other.type == self.EAP_PACKET) ):
                return self.payload.answers(other.payload)
        return 0
    def mysummary(self):
        return self.sprintf("EAPOL %EAPOL.type%")
             

class EAP(Packet):
    name = "EAP"
    fields_desc = [ ByteEnumField("code", 4, { 1:"REQUEST", 2:"RESPONSE", 3:"SUCCESS", 4:"FAILURE" }),
                    ByteField("id", 0),
                    ShortField("len",None),
                    ConditionalField(ByteEnumField("type",0, eap_types), lambda pkt:pkt.code not in [EAP.SUCCESS, EAP.FAILURE]),
                    ConditionalField(StrLenField("identity", "", length_from=lambda pkt:pkt.len - 5), lambda pkt: pkt.code == EAP.RESPONSE and pkt.type == 1),
                    ConditionalField(FieldListField("eap_types", [0x00], ByteEnumField("eap_type", 0x00, eap_types), count_from = lambda pkt:pkt.len - 5), lambda pkt: pkt.code == EAP.RESPONSE and pkt.type == 3)
                                     ]
    
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    TYPE_ID = 1
    TYPE_MD5 = 4
    def answers(self, other):
        if isinstance(other,EAP):
            if self.code == self.REQUEST:
                return 0
            elif self.code == self.RESPONSE:
                if ( (other.code == self.REQUEST) and
                     (other.type == self.type) ):
                    return 1
            elif other.code == self.RESPONSE:
                return 1
        return 0
    
    def post_build(self, p, pay):
        if self.len is None:
            l = len(p)+len(pay)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        return p+pay
             

class EAPOLKey(Packet):
    name = "EAPOL - Key Descriptor Header"
    fields_desc = [ ByteEnumField("desc_type", 2, {1:"RC4",2:"802.11",254:"WPA"}), ]


class EAPOLKeyRC4(Packet):
    name = "EAPOL - Key Descriptor - RC4"
    fields_desc = [ FieldLenField("keylen", None, length_of="key", fmt="H"),
                    LongField("replay", 0),
                    StrFixedLenField("iv", "\x00"*16, 16),
                    BitField("unicast", 0, 1),
                    BitField("index", 0, 7),
                    StrFixedLenField("digest", "\x00"*16, 16),
                    StrLenField("key", "", length_from=lambda x:x.keylen) ]


class EAPOLKeyDot11(Packet):
    name = "EAPOL - Key Descriptor - 802.11"
    fields_desc = [ FlagsField("flags", 0, 13, ["KeyType","res4","res5","Install","ACK",
                                                "MIC","Secure","Error","Request","Encrypted","SMK","res14","res15"]),
                    BitEnumField("version", 1, 3, {1:"MD5/RC4",2:"SHA1/AES"}),
                    ShortField("keylen", 0),
                    LongField("replay", 0),
                    StrFixedLenField("nonce", "\x00"*32, 32),
                    StrFixedLenField("iv", "\x00"*16, 16),
                    StrFixedLenField("rsc", "\x00"*8, 8),
                    LongField("res", 0),
                    StrFixedLenField("mic", "\x00"*16, 16),
                    FieldLenField("keydatalen", None, length_of="keydata", fmt="H"),
                    StrLenField("keydata", "", length_from=lambda x:x.keydatalen) ]
                    
class EAP_TLS(Packet): # eap type 13
    name = "EAP-TLS"
    fields_desc = [ FlagsField("flags", 0, 8, ['reserved5', 'reserved4', 'reserved3', 'reserved2', 'reserved1', 'start', 'fragmented', 'length']),
                    ConditionalField(IntField("length", 0), lambda pkt:pkt.flags > 127),
				]
    
    def guess_payload_class(self, payload):
        if self.flags > 127:
            return scapy.layers.ssl.TLSv1RecordLayer
        else:
            return Packet.guess_payload_class(self, payload)
                    

class LEAP(Packet): # eap type 17
    name = "LEAP"
    fields_desc = [ ByteField("version", 1),
                    ByteField("reserved", 0),
                    FieldLenField("length", None, length_of="data", fmt="B"),
                    StrLenField("data", "", length_from=lambda pkt:pkt.length),
                    StrField("name", "")
                ]


class EAP_TTLS(Packet): # eap type 21
    name = "EAP-TTLS"
    fields_desc = [ FlagsField("flags", 0, 5, ['reserved2', 'reserved1', 'start', 'fragmented', 'length']),
                    BitField("version", 0, 3),
                    ConditionalField(IntField("length", 0), lambda pkt:pkt.flags > 15),
				]
    
    def guess_payload_class(self, payload):
        if self.flags >> 2 in [1, 3, 7]:	# if start bit is set
            return Packet.guess_payload_class(self, payload)
        else:
            return scapy.layers.ssl.TLSv1RecordLayer
            
            
class PEAP(Packet): # eap type 25
    name = "PEAP"
    fields_desc = [ FlagsField("flags", 0, 6, ['reserved3', 'reserved2', 'reserved1', 'start', 'fragmented', 'length']),
                    BitField("version", 0, 2),
                    ConditionalField(IntField("length", 0), lambda pkt:pkt.flags > 31),
                ]
    
    def guess_payload_class(self, payload):
        if self.flags > 31:
            return scapy.layers.ssl.TLSv1RecordLayer
        else:
            return Packet.guess_payload_class(self, payload)
    
           
class EAP_Fast(Packet): # eap type 43
    name = "EAP-Fast"
    fields_desc = [ FlagsField("flags", 0, 5, ['reserved2', 'reserved1', 'start', 'fragmented', 'length']),
                    BitField("version", 0, 3),
                    ConditionalField(IntField("length", 0), lambda pkt:pkt.flags > 15),
                ]
                
    def guess_payload_class(self, payload):
        if self.flags > 15:
            return scapy.layers.ssl.TLSv1RecordLayer
        else:
            return Packet.guess_payload_class(self, payload)


class EAP_Expanded(Packet): # eap type 254
    name = "Expanded EAP"
    fields_desc = [ XThreeBytesField("vendor_id", 0),
                    IntField("vendor_type", 0)
                ]


class WPS(Packet): # eap type 254 vendor id 0x372a
    name = "Wi-Fi Protected Setup"
    fields_desc = [ ByteField("opcode", 1),
                    FlagsField("flags", 0, 8, ['more_flags', 'length']),
                    StrField("data", "")
            ]


# Hardware types - RFC 826 - Extracted from 
# http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml on 24/08/10
# We should add the length of every kind of address.
hardware_types = {   0:"NET/ROM pseudo", # Not referenced by IANA
                     1:"Ethernet",
                     2:"Experimental Ethernet",
                     3:"AX.25",
                     4:"ProNET",
                     5:"Chaos",
                     6:"IEEE 802",
                     7:"ARCNET",
                     8:"Hyperchannel",
                     9:"Lanstar",
                    10:"Autonet",
                    11:"LocalTalk",
                    12:"LocalNet",
                    13:"Ultra link",
                    14:"SMDS",
                    15:"Frame Relay",
                    16:"ATM (Burnett)",
                    17:"HDLC",
                    18:"Fibre Channel",
                    19:"ATM (Forum)",
                    20:"Serial Line",
                    21:"ATM (Burrows)",
                    22:"MIL-STD-188-220",
                    23:"Metricom",
                    24:"IEEE 1394.1995",
                    25:"MAPOS",
                    26:"Twinaxial",
                    27:"EUI-64",
                    28:"HIPARP",
                    29:"ISO 7816-3",
                    30:"ARPSec",
                    31:"IPsec",
                    32:"InfiniBand",
                    33:"P25 CAI",
                    34:"Wiegand",
                    35:"Pure IP",
                    36:"HW_EXP1",
                    37:"HFI",
                   256:"HW_EXP2" }

# http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
arp_opcodes = { 1:"who-has",
                2:"is-at",
                3:"RARP-req",
                4:"RARP-rep",
                5:"Dyn-RARP-req",
                6:"Dyn-RAR-rep",
                7:"Dyn-RARP-err",
                8:"InARP-req",
                9:"InARP-rep",
                10:"ARP-NAK",
                11:"MARS-Req",
                12:"MARS-Multi",
                13:"MARS-MServ",
                14:"MARS-Join",
                15:"MARS-Leave",
                16:"MARS-NAK",
                17:"MARS-Unserv",
                18:"MARS-SJoin",
                19:"MARS-SLeave",
                20:"MARS-Grouplist-Req",
                21:"MARS-Grouplist-Rep",
                22:"MARS-Redirect-Map",
                23:"MAPOS-UNARP",
                24:"OP_EXP1",
                25:"OP_EXP2" }

class ARP(Packet):
    name = "ARP"
    fields_desc = [ ShortEnumField("hwtype", 1, hardware_types),
                    XShortEnumField("ptype", 0x0800, ETHER_TYPES),
                    ByteField("hwlen", 6),
                    ByteField("plen", 4),
                    ShortEnumField("op", 1, arp_opcodes),
                    ARPSourceMACField("hwsrc"),
                    SourceIPField("psrc","pdst"),
                    MACField("hwdst", ETHER_ANY),
                    IPField("pdst", "0.0.0.0") ]
    who_has = 1
    is_at = 2
    def answers(self, other):
        if isinstance(other,ARP):
            if ( (self.op == self.is_at) and
                 (other.op == self.who_has) and
                 (self.psrc == other.pdst) ):
                return 1
        return 0
    def route(self):
        dst = self.pdst
        if isinstance(dst,Gen):
            dst = iter(dst).next()
        return conf.route.route(dst)
    def extract_padding(self, s):
        return "",s
    def mysummary(self):
        if self.op == self.is_at:
            return self.sprintf("ARP is at %hwsrc% says %psrc%")
        elif self.op == self.who_has:
            return self.sprintf("ARP who has %pdst% says %psrc%")
        else:
            return self.sprintf("ARP %op% %psrc% > %pdst%")
                 
conf.neighbor.register_l3(Ether, ARP, lambda l2,l3: getmacbyip(l3.pdst))

class GRErouting(Packet):
    name = "GRE routing informations"
    fields_desc = [ ShortField("address_family",0),
                    ByteField("SRE_offset", 0),
                    FieldLenField("SRE_len", None, "routing_info", "B"),
                    StrLenField("routing_info", "", length_from=lambda x:x.SRE_len),
                    ]


class GRE(Packet):
    name = "GRE"
    fields_desc = [ BitField("chksum_present",0,1),
                    BitField("routing_present",0,1),
                    BitField("key_present",0,1),
                    BitField("seqnum_present",0,1),
                    BitField("strict_route_source",0,1),
                    BitField("recursion_control",0,3),
                    BitField("flags",0,5),
                    BitField("version",0,3),
                    XShortEnumField("proto", 0x0000, ETHER_TYPES),
                    ConditionalField(XShortField("chksum",None), lambda pkt:pkt.chksum_present==1 or pkt.routing_present==1),
                    ConditionalField(XShortField("offset",None), lambda pkt:pkt.chksum_present==1 or pkt.routing_present==1),
                    ConditionalField(XIntField("key",None), lambda pkt:pkt.key_present==1),
                    ConditionalField(XIntField("seqence_number",None), lambda pkt:pkt.seqnum_present==1),
                    ]
    def post_build(self, p, pay):
        p += pay
        if self.chksum_present and self.chksum is None:
            c = checksum(p)
            p = p[:4]+chr((c>>8)&0xff)+chr(c&0xff)+p[6:]
        return p




bind_layers( Dot3,          LLC,           )
# bind_layers( Ether,         Dot1Q,         type=0x8100)
bind_layers( Ether,         ARP,           type=0x0806)
bind_layers( Ether,         EAPOL,         type=0x888E)
bind_layers( Ether,         EAPOL,         dst='01:80:c2:00:00:03', type=0x888E)
bind_layers( CookedLinux,   LLC,           proto=122)
# bind_layers( CookedLinux,   Dot1Q,         proto=0x8100)
bind_layers( CookedLinux,   Ether,         proto=1)
bind_layers( CookedLinux,   ARP,           proto=0x0806)
bind_layers( CookedLinux,   EAPOL,         proto=0x888E)
bind_layers( GRE,           LLC,           proto=122)
# bind_layers( GRE,           Dot1Q,         proto=0x8100)
bind_layers( GRE,           Ether,         proto=1)
bind_layers( GRE,           ARP,           proto=0x0806)
bind_layers( GRE,           EAPOL,         proto=0x888E)
bind_layers( GRE,           GRErouting,    { "routing_present" : 1 } )
bind_layers( GRErouting,    Raw,           { "address_family" : 0, "SRE_len" : 0 })
bind_layers( GRErouting,    GRErouting,    { } )
bind_layers( EAPOL,         EAP,           type=0)
bind_layers( EAPOL,         EAPOLKey,      type=3)
bind_layers( EAP,           EAP_TLS,       type=13)
bind_layers( EAP,           LEAP,          type=17)
bind_layers( EAP,           EAP_TTLS,      type=21)
bind_layers( EAP,           PEAP,          type=25)
bind_layers( EAP,           EAP_Fast,      type=43)
bind_layers( EAP,           EAP_Expanded,  type=254)
bind_layers( EAP_Expanded,  WPS,           vendor_id=0x372a)
bind_layers( EAPOLKey,      EAPOLKeyRC4,   desc_type=1)
bind_layers( EAPOLKey,      EAPOLKeyDot11, desc_type=254) #XXX: in what standard is this defined?
bind_layers( EAPOLKey,      EAPOLKeyDot11, desc_type=2)
bind_layers( LLC,           STP,           dsap=66, ssap=66, ctrl=3)
bind_layers( LLC,           SNAP,          dsap=170, ssap=170, ctrl=3)
# bind_layers( SNAP,          Dot1Q,         code=0x8100)
bind_layers( SNAP,          Ether,         code=1)
bind_layers( SNAP,          ARP,           code=0x0806)
bind_layers( SNAP,          EAPOL,         code=0x888E)
bind_layers( SNAP,          STP,           code=267)

conf.l2types.register(ARPHDR_ETHER, Ether)
conf.l2types.register_num2layer(ARPHDR_METRICOM, Ether)
conf.l2types.register_num2layer(ARPHDR_LOOPBACK, Ether)
conf.l2types.register_layer2num(ARPHDR_ETHER, Dot3)
conf.l2types.register(113, CookedLinux)
conf.l2types.register(144, CookedLinux)  # called LINUX_IRDA, similar to CookedLinux

conf.l3types.register(ETH_P_ARP, ARP)




### Technics



@conf.commands.register
def arpcachepoison(target, victim, interval=60):
    """Poison target's cache with (your MAC,victim's IP) couple
arpcachepoison(target, victim, [interval=60]) -> None
"""
    tmac = getmacbyip(target)
    p = Ether(dst=tmac)/ARP(op="who-has", psrc=victim, pdst=target)
    try:
        while 1:
            sendp(p, iface_hint=target)
            if conf.verb > 1:
                os.write(1,".")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass


class ARPingResult(SndRcvList):
    def __init__(self, res=None, name="ARPing", stats=None):
        SndRcvList.__init__(self, res, name, stats)

    def show(self):
        for s,r in self.res:
            print r.sprintf("%19s,Ether.src% %ARP.psrc%")



@conf.commands.register
def arping(net, timeout=2, cache=0, verbose=None, **kargs):
    """Send ARP who-has requests to determine which hosts are up
arping(net, [cache=0,] [iface=conf.iface,] [verbose=conf.verb]) -> None
Set cache=True if you want arping to modify internal ARP-Cache"""
    if verbose is None:
        verbose = conf.verb
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=net), verbose=verbose,
                    filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
    ans = ARPingResult(ans.res)

    if cache and ans is not None:
        for pair in ans:
            conf.netcache.arp_cache[pair[1].psrc] = (pair[1].hwsrc, time.time())
    if verbose:
        ans.show()
    return ans,unans

@conf.commands.register
def is_promisc(ip, fake_bcast="ff:ff:00:00:00:00",**kargs):
    """Try to guess if target is in Promisc mode. The target is provided by its ip."""

    responses = srp1(Ether(dst=fake_bcast) / ARP(op="who-has", pdst=ip),type=ETH_P_ARP, iface_hint=ip, timeout=1, verbose=0,**kargs)

    return responses is not None

@conf.commands.register
def promiscping(net, timeout=2, fake_bcast="ff:ff:ff:ff:ff:fe", **kargs):
    """Send ARP who-has requests to determine which hosts are in promiscuous mode
    promiscping(net, iface=conf.iface)"""
    ans,unans = srp(Ether(dst=fake_bcast)/ARP(pdst=net),
                    filter="arp and arp[7] = 2", timeout=timeout, iface_hint=net, **kargs)
    ans = ARPingResult(ans.res, name="PROMISCPing")

    ans.display()
    return ans,unans


class ARP_am(AnsweringMachine):
    function_name="farpd"
    filter = "arp"
    send_function = staticmethod(sendp)

    def parse_options(self, IP_addr=None, iface=None, ARP_addr=None):
        self.IP_addr=IP_addr
        self.iface=iface
        self.ARP_addr=ARP_addr

    def is_request(self, req):
        return (req.haslayer(ARP) and
                req.getlayer(ARP).op == 1 and
                (self.IP_addr == None or self.IP_addr == req.getlayer(ARP).pdst))
    
    def make_reply(self, req):
        ether = req.getlayer(Ether)
        arp = req.getlayer(ARP)
        iff,a,gw = conf.route.route(arp.psrc)
        if self.iface != None:
            iff = self.iface
        ARP_addr = self.ARP_addr
        IP_addr = arp.pdst
        resp = Ether(dst=ether.src,
                     src=ARP_addr)/ARP(op="is-at",
                                       hwsrc=ARP_addr,
                                       psrc=IP_addr,
                                       hwdst=arp.hwsrc,
                                       pdst=arp.pdst)
        return resp

    def sniff(self):
        sniff(iface=self.iface, **self.optsniff)

@conf.commands.register
def etherleak(target, **kargs):
    """Exploit Etherleak flaw"""
    return srpflood(Ether()/ARP(pdst=target), prn=lambda (s,r): Padding in r and hexstr(r[Padding].load),
                    filter="arp", **kargs)


import scapy.layers.ssl
