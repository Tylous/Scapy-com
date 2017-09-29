## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
ISAKMP (Internet Security Association and Key Management Protocol).
"""

import struct
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import IP,UDP
from scapy.sendrecv import sr
from scapy.layers.inet6 import IP6Field


# see http://www.iana.org/assignments/ipsec-registry for details
ISAKMPAttrPhase1Types = {  1:("Encryption", { 1:"DES-CBC",
                                              2:"IDEA-CBC",
                                              3:"Blowfish-CBC",
                                              4:"RC5-R16-B64-CBC",
                                              5:"3DES-CBC", 
                                              6:"CAST-CBC", 
                                              7:"AES-CBC", 
                                              8:"CAMELLIA-CBC" }, 1),
                           2:("Hash", { 1:"MD5",
                                        2:"SHA",
                                        3:"Tiger",
                                        4:"SHA2-256",
                                        5:"SHA2-384",
                                        6:"SHA2-512" }, 1),
                           3:("Authentication", {     1:"PSK", 
                                                      2:"DSS",
                                                      3:"RSA Sig",
                                                      4:"RSA Encryption",
                                                      5:"RSA Encryption Revised",
                                                      6:"ElGamal Encryption",
                                                      7:"ElGamal Encryption Revised",
                                                      8:"ECDSA Sig",
                                                      9:"ECDSA-256",
                                                     10:"ECDSA-384",
                                                     11:"ECDSA-521",
                                                  64221:"HybridInitRSA",
                                                  64222:"HybridRespRSA",
                                                  64223:"HybridInitDSS",
                                                  64224:"HybridRespDSS",
                                                  65001:"XAUTHInitPreShared",
                                                  65002:"XAUTHRespPreShared",
                                                  65003:"XAUTHInitDSS",
                                                  65004:"XAUTHRespDSS",
                                                  65005:"XAUTHInitRSA",
                                                  65006:"XAUTHRespRSA",
                                                  65007:"XAUTHInitRSAEncryption",
                                                  65008:"XAUTHRespRSAEncryption",
                                                  65009:"XAUTHInitRSARevisedEncryption",
                                                  65010:"XAUTHRespRSARevisedEncryption" }, 1),
                           4:("GroupDesc", {  1:"768MODPgr",
                                              2:"1024MODPgr", 
                                              3:"EC2Ngr155",
                                              4:"EC2Ngr185",
                                              5:"1536MODPgr", 
                                              6:"EC2Ngr163r1",
                                              7:"EC2Ngr163k1",
                                              8:"EC2Ngr283r1",
                                              9:"EC2Ngr283k1",
                                             10:"EC2Ngr409r1",
                                             11:"EC2Ngr409k1",
                                             12:"EC2Ngr571r1",
                                             13:"EC2Ngr571k1",
                                             14:"2048MODPgr", 
                                             15:"3072MODPgr", 
                                             16:"4096MODPgr", 
                                             17:"6144MODPgr", 
                                             18:"8192MODPgr", 
                                             19:"256ECPgr",
                                             20:"384ECPgr",
                                             21:"521ECPgr",
                                             22:"1024MODPgr160PO",
                                             23:"2048MODPgr224PO",
                                             24:"2048MODPgr256PO",
                                             25:"192ECPgr",
                                             26:"224ECPgr" }, 1),
                           5:("GroupType", { 1:"MODP",
                                             2:"ECP",
                                             3:"EC2N" }, 1),
                           6:("GroupPrime", {}, 0),
                           7:("GroupGen1", {}, 0),
                           8:("GroupGen2", {}, 0),
                           9:("GroupCurveA", {}, 0),
                          10:("GroupCurveB", {}, 0),
                          11:("LifeType", { 1:"Seconds",
                                            2:"Kilobytes" }, 1),
                          12:("LifeDuration", {}, 0),
                          13:("PRF", {}, 1),
                          14:("KeyLength", {}, 1),
                          15:("FieldSize", {}, 1),
                          16:("GroupOrder", {}, 0) }

# http://www.iana.org/assignments/isakmp-registry
ISAKMPAttrIPSECTypes = {  1:("SALifeType", { 1:"Seconds",
                                             2:"Kilobytes" }, 1),
                          2:("SALifeDuration", {}, 0),
                          3:("GroupDesc", {}, 1),
                          4:("Encapsulation", { 1:"Tunnel",
                                                2:"Transport",
                                                3:"UDP-Encapsulated-Tunnel",
                                                4:"UDP-Encapsulated-Transport" }, 1),
                          5:("Authentication", {  1:"HMAC-MD5",
                                                  2:"HMAC-SHA",
                                                  3:"DES-MAC",
                                                  4:"KPDK",
                                                  5:"HMAC-SHA2-256",
                                                  6:"HMAC-SHA2-384",
                                                  7:"HMAC-SHA2-512",
                                                  8:"HMAC-RIPEMD",
                                                  9:"AES-XCBC-MAC",
                                                 10:"SIG-RSA",
                                                 11:"AES-128-GMAC",
                                                 12:"AES-192-GMAC",
                                                 13:"AES-256-GMAC" }, 1),
                          6:("KeyLength", {}, 1),
                          7:("KeyRounds", {}, 1),
                          8:("CompressDictSize", {}, 1),
                          9:("CompressPrivateAlgorithm", {}, 0),
                         10:("ECNTunnel", { 1:"Allowed" ,
                                            2:"Forbidden" }, 1),
                         11:("ExtendedSeqNum", { 1:"64-bit" }, 1),
                         12:("AuthKeyLength", {}, 0),
                         13:("SigEncoding", { 1:"RSASSA-PKCS1-v1_5",
                                              2:"RSASSA-PSS" }, 1) }

# RFC3547
ISAKMPAttrKEKClasses = { 1:("KEK_MANAGEMENT_ALGORITHM", { 1:"LKH" }, 1),
                         2:("KEK_ALGORITHM", { 1:"KEK_ALG_DES",
                                               2:"KEK_ALG_3DES",
                                               3:"UDP-KEK_ALG_AES-Tunnel" }, 1),
                         3:("KEK_KEY_LENGTH", {}, 1),
                         4:("KEK_KEY_LIFETIME", {}, 0),
                         5:("SIG_HASH_ALGORITHM", { 1:"SIG_HASH_MD5",
                                                    2:"SIG_HASH_SHA1", }, 1),
                         6:("SIG_ALGORITHM", { 1:"SIG_ALG_RSA",
                                               2:"SIG_ALG_DSS",
                                               3:"SIG_ALG_ECDSS" }, 1),
                         7:("SIG_KEY_LENGTH", {}, 1),
                         8:("KE_OAKLEY_GROUP", {}, 1) }


class RandISAKMPAttributes(RandField):
    def __init__(self, types, size=None, all=False):
        self.types = types
        if size is None:
            size = RandNumExpo(0.1)
        self.size = size
        self.all = all
    def _fix(self):
        trans = []
        if self.all:
            keys = self.types.keys()
            random.shuffle(keys)
        else:
            keys = [random.choice(self.types.keys())
                    for _ in range(self.size)]
        for typ in keys:
            type_val,enc_dict,af_bit = self.types.get(typ)
            is_tlv = not af_bit
            if len(enc_dict) > 0:
                val = random.choice(enc_dict.keys())
            else:
                if is_tlv:
                    val = RandNum(0,2**128-1)
                else:
                    val = RandNum(0,2**16-1)
            trans.append((typ, val))
        return trans


class ISAKMPAttributesField(StrLenField):
    islist=1
    def __init__(self, name, default, types, length_from=None):
        StrLenField.__init__(self, name, default, length_from=length_from)
        self.types = types
        self.names = {}
        for n in types:
            self.names[types[n][0]] = n
    def name2type(self, tv):
        typ,val = tv[0],tv[1]
        if type(typ) is str:
            if typ in self.names:
                typ = self.names[typ]
            else:
                warning("Ignoring invalid ISAKMP attribute type %r" % tv[0])
                return None
        if type(val) is str:
            enc_dict = self.types.get(typ,(typ,{}))[1]
            for k in enc_dict:
                if enc_dict[k] == val:
                    val = k
                    break
            else:
                warning("Ignoring invalid ISAKMP attribute value %r for type %r" % (tv[1],tv[0]))
                return None
        if len(tv) > 2:
            return (typ,val,tv[2])
        else:
            return (typ,val)
    def type2name(self, typ, enc):
        val = self.types.get(typ,(typ,{}))
        if type(enc) is str:
            enc = repr(enc)
        else:
            enc = val[1].get(enc,enc)
        return (val[0],enc)
    def h2i(self, pkt, h):
        if not h:
            return []
        return filter(lambda x:x is not None, map(self.name2type, h))
    def i2m(self, pkt, i):
        m = ""
        for tv in i:
            typ,val = tv[0],tv[1]
            if len(tv) > 2:
                vlen = tv[2]
            else:
                vlen = 0
            name,enc_dict,af_bit = self.types.get(typ,(typ,{},None))
            s = ""
            if af_bit == 0 or (val & ~0xffff):
                if af_bit == 1:
                    warning("%r should not be TLV but is too big => using TLV encoding" % name)
                n = 0
                while val or vlen > 0:
                    s = chr(val&0xff)+s
                    val >>= 8
                    vlen -= 1
                    n += 1
                val = n
            else:
                typ |= 0x8000
            m += struct.pack("!HH",typ, val)+s
        return m
    def m2i(self, pkt, m):
        # I try to ensure that we don't read off the end of our packet based
        # on bad length fields we're provided in the packet. There are still
        # conditions where struct.unpack() may not get enough packet data, but
        # worst case that should result in broken attributes (which would
        # be expected). (wam)
        lst = []
        while len(m) >= 4:
            trans_type, = struct.unpack("!H", m[:2])
            is_tlv = not (trans_type & 0x8000)
            if is_tlv:
                # We should probably check to make sure the attribute type we
                # are looking at is allowed to have a TLV format and issue a 
                # warning if we're given an TLV on a basic attribute.
                value_len, = struct.unpack("!H", m[2:4])
                if value_len+4 > len(m):
                    warning("Bad length for ISAKMP attribute type=%#6x" % trans_type)
                value = m[4:4+value_len]
                value = reduce(lambda x,y: (x<<8L)|y, struct.unpack("!%s" % ("B"*len(value),), value),0)
            else:
                trans_type &= 0x7fff
                value_len=0
                value, = struct.unpack("!H", m[2:4])
            m=m[4+value_len:]
            if value_len:
                lst.append((trans_type, value, value_len))
            else:
                lst.append((trans_type, value))
        if len(m) > 0:
            warning("Extra bytes after ISAKMP attribute dissection [%r]" % m)
        return lst
    def i2repr(self, pkt, x):
        lst = ["(%s: %s)" % self.type2name(tv[0],tv[1]) for tv in x]
        return "[%s]" % ", ".join(lst)
    def randval(self):
        return RandISAKMPAttributes(self.types)


class ISAKMPTransformsField(PacketListField): #XXX: need to set next_payload
    def __init__(self, name, default, count_from=None, length_from=None):
        PacketListField.__init__(self, name, default,
                                 ISAKMP_payload_Transform, count_from, length_from)
    def m2i(self, pkt, m):
        if pkt.proto == 2:
            return ISAKMP_payload_Transform_AH(m)
        elif pkt.proto == 3:
            return ISAKMP_payload_Transform_ESP(m)
        else:
            return ISAKMP_payload_Transform(m)


ISAKMP_payload_type = ["None","SA","Proposal","Transform","KE","ID","CERT","CR","Hash",
                       "SIG","Nonce","Notification","Delete","VendorID",
                       "reserved","SAK","SAT","KD","SEQ","POP","NAT_D","NAT_OA"]

ISAKMP_exchange_type = {  0:"None",
                          1:"base",
                          2:"identity prot.",
                          3:"auth only",
                          4:"aggressive",
                          5:"info",
                         32:"quick mode",
                         33:"new group mode" }


class ISAKMP(Packet): # rfc2408
    name = "ISAKMP"
    fields_desc = [
        StrFixedLenField("init_cookie","",8),
        StrFixedLenField("resp_cookie","",8),
        ByteEnumField("next_payload",0,ISAKMP_payload_type),
        XByteField("version",0x10),
        ByteEnumField("exch_type",0,ISAKMP_exchange_type),
        FlagsField("flags",0, 8, ["encryption","commit","auth_only"]),
        IntField("id",0),
        IntField("length",None)
        ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return Raw # encrypted payload
        else:
            return Packet.guess_payload_class(self, payload)
    def default_payload_class(self, payload):
        return ISAKMP_payload

    def answers(self, other):
        if isinstance(other, ISAKMP):
            if other.init_cookie == self.init_cookie:
                return 1
        return 0
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24]+struct.pack("!I",len(p))+p[28:]
        return p
       

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_proto_ID = { 1: "PROTO_ISAKMP",
                    2: "PROTO_IPSEC_AH",
                    3: "PROTO_IPSEC_ESP",
                    4: "PROTO_IPCOMP",
                    5: "PROTO_GIGABEAM_RADIO" }

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_trans_ID = { 1:"KEY_IKE" }
ISAKMP_trans_ID_AH = {  2:"AH_MD5",
                        3:"AH_SHA",
                        4:"AH_DES",
                        5:"AH_SHA2-256",
                        6:"AH_SHA2-384",
                        7:"AH_SHA2-512",
                        8:"AH_RIPEMD",
                        9:"AH_AES-XCBC-MAC",
                       10:"AH_RSA",
                       11:"AH_AES-128-GMAC",
                       12:"AH_AES-192-GMAC",
                       13:"AH_AES-256-GMAC" }
ISAKMP_trans_ID_ESP = {  1:"ESP_DES_IV64",
                         2:"ESP_DES",
                         3:"ESP_3DES",
                         4:"ESP_RC5",
                         5:"ESP_IDEA",
                         6:"ESP_CAST",
                         7:"ESP_BLOWFISH",
                         8:"ESP_3IDEA",
                         9:"ESP_DES_IV32",
                        10:"ESP_RC4",
                        11:"ESP_NULL",
                        12:"ESP_AES-CBC",
                        13:"ESP_AES-CTR",
                        14:"ESP_AES-CCM_8",
                        15:"ESP_AES-CCM_12",
                        16:"ESP_AES-CCM_16",
                        18:"ESP_AES-GCM_8",
                        19:"ESP_AES-GCM_12",
                        20:"ESP_AES-GCM_16",
                        21:"ESP_SEED_CBC",
                        22:"ESP_CAMELLIA",
                        23:"ESP_NULL_AUTH_AES-GMAC" }
ISAKMP_trans_ID_IPCOMP = {  1:"IPCOMP_OUI",
                            2:"IPCOMP_DEFLATE",
                            3:"IPCOMP_LZS",
                            4:"IPCOMP_LZJH" }

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_ID_type = {  1: "IPV4_ADDR",
                    2: "FQDN",
                    3: "USER_FQDN",
                    4: "IPV4_ADDR_SUBNET",
                    5: "IPV6_ADDR",
                    6: "IPV6_ADDR_SUBNET",
                    7: "IPV4_ADDR_RANGE",
                    8: "IPV6_ADDR_RANGE",
                    9: "DER_ASN1_DN",
                   10: "DER_ASN1_GN",
                   11: "KEY_ID",
                   12: "LIST" }

# RFC2408, http://www.iana.org/assignments/ikev2-parameters
ISAKMP_cert_encoding = {  0: "NONE",
                          1: "PKCS #7 wrapped X.509 certificate",
                          2: "PGP Certificate",
                          3: "DNS Signed Key",
                          4: "X.509 Certificate - Signature",
                          5: "X.509 Certificate - Key Exchange",
                          6: "Kerberos Token",
                          7: "Certificate Revocation List (CRL)",
                          8: "Authority Revocation List (ARL)",
                          9: "SPKI Certificate",
                         10: "X.509 Certificate - Attribute",
                         11: "Raw RSA Key",
                         12: "Hash and URL of X.509 certificate",
                         13: "Hash and URL of X.509 bundle",
                         14: "OCSP Content" }

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_DOI = { 0: "ISAKMP",
               1: "IPSEC",
               2: "GDOI" }

# RFC2408, http://www.iana.org/assignments/isakmp-registry
ISAKMP_notify_message = {     1: "INVALID-PAYLOAD-TYPE",
                              2: "DOI-NOT-SUPPORTED",
                              3: "SITUATION-NOT-SUPPORTED",
                              4: "INVALID-COOKIE",
                              5: "INVALID-MAJOR-VERSION",
                              6: "INVALID-MINOR-VERSION",
                              7: "INVALID-EXCHANGE-TYPE",
                              8: "INVALID-FLAGS",
                              9: "INVALID-MESSAGE-ID",
                             10: "INVALID-PROTOCOL-ID",
                             11: "INVALID-SPI",
                             12: "INVALID-TRANSFORM-ID",
                             13: "ATTRIBUTES-NOT-SUPPORTED",
                             14: "NO-PROPOSAL-CHOSEN",
                             15: "BAD-PROPOSAL-SYNTAX",
                             16: "PAYLOAD-MALFORMED",
                             17: "INVALID-KEY-INFORMATION",
                             18: "INVALID-ID-INFORMATION",
                             19: "INVALID-CERT-ENCODING",
                             20: "INVALID-CERTIFICATE",
                             21: "CERT-TYPE-UNSUPPORTED",
                             22: "INVALID-CERT-AUTHORITY",
                             23: "INVALID-HASH-INFORMATION",
                             24: "AUTHENTICATION-FAILED",
                             25: "INVALID-SIGNATURE",
                             26: "ADDRESS-NOTIFICATION",
                             27: "NOTIFY-SA-LIFETIME",
                             28: "CERTIFICATE-UNAVAILABLE",
                             29: "UNSUPPORTED-EXCHANGE-TYPE",
                             30: "UNEQUAL-PAYLOAD-LENGTHS",
                          24576: "RESPONDER-LIFETIME",
                          24577: "REPLAY-STATUS",
                          24578: "INITIAL-CONTACT" }


class _ISAKMP_payload_HDR(Packet):
    name = "Abstract ISAKMP payload header"
    fields_desc = [
        ByteEnumField("next_payload",0,ISAKMP_payload_type),
        ByteField("res",0),
        ShortField("length",None),
        ]


class ISAKMP_payload(Packet):
    name = "ISAKMP unknown payload"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]
    def default_payload_class(self, payload):
        return ISAKMP_payload
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        p += pay
        return p


class ISAKMP_payload_Transform(ISAKMP_payload):
    name = "ISAKMP Transform"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("num",None),
        ByteEnumField("id",1,ISAKMP_trans_ID),
        ShortField("res2",0),
        ISAKMPAttributesField("transforms",[],ISAKMPAttrPhase1Types,
                              length_from=lambda x:x.length-8)
        ]

class ISAKMP_payload_Transform_AH(ISAKMP_payload_Transform):
    name = "ISAKMP Transform (AH)"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("num",None),
        ByteEnumField("id",1,ISAKMP_trans_ID_AH),
        ShortField("res2",0),
        ISAKMPAttributesField("transforms",[],ISAKMPAttrIPSECTypes,
                              length_from=lambda x:x.length-8)
        ]

class ISAKMP_payload_Transform_ESP(ISAKMP_payload_Transform):
    name = "ISAKMP Transform (ESP)"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("num",None),
        ByteEnumField("id",1,ISAKMP_trans_ID_ESP),
        ShortField("res2",0),
        ISAKMPAttributesField("transforms",[],ISAKMPAttrIPSECTypes,
                              length_from=lambda x:x.length-8)
        ]

class ISAKMP_payload_Transform_IPCOMP(ISAKMP_payload_Transform):
    name = "ISAKMP Transform (IPCOMP)"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("num",None),
        ByteEnumField("id",1,ISAKMP_trans_ID_IPCOMP),
        ShortField("res2",0),
        ISAKMPAttributesField("transforms",[],ISAKMPAttrPhase1Types,
                              length_from=lambda x:x.length-8)
        ]
            

        
class ISAKMP_payload_Proposal(ISAKMP_payload):
    name = "ISAKMP Proposal"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("proposal",1),
        ByteEnumField("proto",1,ISAKMP_proto_ID),
        FieldLenField("SPIsize",None,"SPI","B"),
        FieldLenField("trans_nb",None,count_of="trans",fmt="B"),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        ISAKMPTransformsField("trans",[],length_from=lambda x:x.length-8),
        ]
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        p += pay
        return p


class ISAKMP_payload_VendorID(ISAKMP_payload):
    name = "ISAKMP Vendor ID"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_SA(ISAKMP_payload):
    name = "ISAKMP SA"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntEnumField("DOI",1,ISAKMP_DOI),
        FlagsField("situation",1,32,["SIT_IDENTITY_ONLY","SIT_SECRECY","SIT_INTEGRITY"]),
        PacketLenField("prop",Raw(),ISAKMP_payload_Proposal,length_from=lambda x:x.length-12),
        ]

class ISAKMP_payload_Nonce(ISAKMP_payload):
    name = "ISAKMP Nonce"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("nonce","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_KE(ISAKMP_payload):
    name = "ISAKMP Key Exchange"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("keyexch","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_ID(ISAKMP_payload):
    name = "ISAKMP Identification"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("IDtype",1,ISAKMP_ID_type),
        ByteEnumField("proto",0,{0:"Unused"}),
        ShortEnumField("port",0,{0:"Unused"}),
        ConditionalField(IPField("addr4","127.0.0.1"),
                         lambda pkt:pkt.IDtype in [1,4,7]),
        ConditionalField(IPField("addr4sub","255.255.255.0"),
                         lambda pkt:pkt.IDtype == 4),
        ConditionalField(IPField("addr4end","127.0.0.1"),
                         lambda pkt:pkt.IDtype == 7),
        ConditionalField(IP6Field("addr6","::1"),
                         lambda pkt:pkt.IDtype in [5,6,8]),
        ConditionalField(IP6Field("addr6sub","ffff:ffff:ffff:ffff::"),
                         lambda pkt:pkt.IDtype == 6),
        ConditionalField(IP6Field("addr6end","::1"),
                         lambda pkt:pkt.IDtype == 8),
        ConditionalField(StrLenField("domain","",length_from=lambda x:x.length-8),
                         lambda pkt:pkt.IDtype in [2,3]),
        ConditionalField(StrLenField("load","",length_from=lambda x:x.length-8),
                         lambda pkt:pkt.IDtype in [9,10,11] or pkt.IDtype > 12),
        #ConditionalField(PacketListField("IDlist",... # self-reference, can't define here
        ]
ISAKMP_payload_ID.fields_desc.append(
    ConditionalField(PacketListField("IDlist",[],ISAKMP_payload_ID,length_from=lambda x:x.length-8),
                     lambda pkt:pkt.IDtype == 12)) # class must be defined first

class ISAKMP_payload_Hash(ISAKMP_payload):
    name = "ISAKMP Hash"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("hash","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_CERT(ISAKMP_payload):
    name = "ISAKMP Certificate"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("encoding",0,ISAKMP_cert_encoding),
        StrLenField("cert","",length_from=lambda x:x.length-5),
        ]

class ISAKMP_payload_CR(ISAKMP_payload_CERT):
    name = "ISAKMP Certificate Request"

class ISAKMP_payload_SIG(ISAKMP_payload):
    name = "ISAKMP Signature"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("sig","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_Notification(ISAKMP_payload):
    name = "ISAKMP Notification"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntEnumField("DOI",0,ISAKMP_DOI),
        ByteEnumField("proto",1,ISAKMP_proto_ID),
        FieldLenField("SPIsize",None,"SPI","B"),
        ShortEnumField("message",0,ISAKMP_notify_message),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        StrLenField("data","",length_from=lambda x:x.length-12),
        ]

class ISAKMP_payload_Delete(ISAKMP_payload):
    name = "ISAKMP Delete"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntEnumField("DOI",0,ISAKMP_DOI),
        ByteEnumField("proto",1,ISAKMP_proto_ID),
        ByteField("SPIsize",16),
        FieldLenField("SPI_nb",None,count_of="SPIs",fmt="H"),
        FieldListField("SPIs", [], StrLenField("SPI","",length_from=lambda x:x.SPIsize),
                       count_from=lambda x:x.SPI_nb)
        ]

class ISAKMP_payload_SAK(ISAKMP_payload):
    name = "ISAKMP SA KEK"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("proto",0,IP_PROTOS),
        ByteEnumField("stype",1,ISAKMP_ID_type),
        ShortEnumField("sport",80,TCP_SERVICES),
        FieldLenField("slen",None,"sdata","B"),
        StrLenField("sdata","",length_from=lambda x:x.slen),
        ByteEnumField("dtype",1,ISAKMP_ID_type), #XXX: is there a "DST ID Prot" field?
        ShortEnumField("dport",80,TCP_SERVICES),
        FieldLenField("dlen",None,"ddata","B"),
        StrLenField("ddata","",length_from=lambda x:x.dlen),
        StrFixedLenField("SPI","\x00"*16,16),
        ShortEnumField("pop_algo",0,{1:"RSA",2:"DSS",3:"ECDSS"}),
        ShortField("pop_key_len",0), #XXX: FieldLenField?
        ISAKMPAttributesField("kek",[],ISAKMPAttrKEKClasses,
                              length_from=lambda x:x.length-33),
        ]

class ISAKMP_payload_SAT(ISAKMP_payload):
    name = "ISAKMP SA TEK"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("id",1,{1:"IPSEC_ESP"}),
        ByteEnumField("proto",0,IP_PROTOS),
        ByteEnumField("stype",1,ISAKMP_ID_type),
        ShortEnumField("sport",80,TCP_SERVICES),
        FieldLenField("slen",None,"sdata","B"),
        StrLenField("sdata","",length_from=lambda x:x.slen),
        ByteEnumField("dtype",1,ISAKMP_ID_type), #XXX: is there a "DST ID Prot" field?
        ShortEnumField("dport",80,TCP_SERVICES),
        FieldLenField("dlen",None,"ddata","B"),
        StrLenField("ddata","",length_from=lambda x:x.dlen),
        ByteEnumField("trans_id",1,{1:"KEY_IKE"}),
        StrFixedLenField("SPI","\x00"*4,4),
        ISAKMPAttributesField("attrs",[],ISAKMPAttrIPSECTypes,
                              length_from=lambda x:x.length-19),
        ]

class ISAKMP_key(Packet):
    name = "ISAKMP Key Packet for KD"
    fields_desc = [
        ByteEnumField("type",0,{1:"TEK",2:"KEK",3:"LKH"}),
        ByteField("res",0),
        ShortField("length",None),
        FieldLenField("SPIsize",None,"SPI","B"),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        StrLenField("attrs","",length_from=lambda x:x.length-8), #TODO: key attributes
        ]
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        p += pay
        return p

class ISAKMP_payload_KD(ISAKMP_payload):
    name = "ISAKMP Key Download"
    fields_desc = [
        _ISAKMP_payload_HDR,
        FieldLenField("num",None,count_of="keys",fmt="H"),
        ShortField("res2",0),
        PacketListField("keys",[],ISAKMP_key,length_from=lambda x:x.length-8),
        ]

class ISAKMP_payload_SEQ(ISAKMP_payload):
    name = "ISAKMP Sequence Number"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntField("seq",0),
        ]

class ISAKMP_payload_POP(ISAKMP_payload_SIG):
    name = "ISAKMP Proof of Possession"

class ISAKMP_payload_NAT_D(ISAKMP_payload_Hash):
    name = "ISAKMP NAT Discovery"

class ISAKMP_payload_NAT_OA(ISAKMP_payload):
    name = "ISAKMP NAT Original Address"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("IDtype",1,ISAKMP_ID_type),
        ByteField("res2",0),
        ShortField("res3",0),
        ConditionalField(IPField("addr4","127.0.0.1"),lambda pkt:pkt.IDtype==1),
        ConditionalField(IP6Field("addr6","::1"),lambda pkt:pkt.IDtype==5),
        ConditionalField(StrLenField("load","",length_from=lambda x:x.length-8),
                         lambda pkt:pkt.IDtype not in [1,5]),
        ]


_ISAKMP_payload_layers = {}
for i in range(len(ISAKMP_payload_type)):
    n = "ISAKMP_payload_%s" % ISAKMP_payload_type[i]
    if n in globals():
        _ISAKMP_payload_layers[i] = globals()[n]
_ISAKMP_layers = [ISAKMP,ISAKMP_payload] + _ISAKMP_payload_layers.values()

for i in _ISAKMP_layers:
    for k,v in _ISAKMP_payload_layers.iteritems():
        bind_layers(i, v, next_payload=k)
    bind_layers(i, ISAKMP_payload)
del(i,n,k,v)

bind_layers( UDP,           ISAKMP,        sport=500)
bind_layers( UDP,           ISAKMP,        dport=500)
bind_layers( UDP,           ISAKMP,        dport=500, sport=500)


def ikescan(ip):
    return sr(IP(dst=ip)/UDP()/ISAKMP(init_cookie=RandString(8),
                                      exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal()))

