## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
SNMP (Simple Network Management Protocol).
"""

import struct,hashlib
from scapy.asn1packet import *
from scapy.asn1fields import *
from scapy.layers.inet import IP,UDP,ICMP
from scapy.sendrecv import sr1
try:
    from Crypto.Cipher import DES,AES
except ImportError:
    pass

##########
## SNMP ##
##########

######[ ASN1 class ]######

class ASN1_Class_SNMP(ASN1_Class_UNIVERSAL):
    name="SNMP"
    PDU_GET = 0xa0
    PDU_NEXT = 0xa1
    PDU_RESPONSE = 0xa2
    PDU_SET = 0xa3
    PDU_TRAPv1 = 0xa4
    PDU_BULK = 0xa5
    PDU_INFORM = 0xa6
    PDU_TRAPv2 = 0xa7
    PDU_REPORT = 0xa8


class ASN1_SNMP_PDU_GET(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_GET

class ASN1_SNMP_PDU_NEXT(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT

class ASN1_SNMP_PDU_RESPONSE(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_RESPONSE

class ASN1_SNMP_PDU_SET(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_SET

class ASN1_SNMP_PDU_TRAPv1(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv1

class ASN1_SNMP_PDU_BULK(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_BULK

class ASN1_SNMP_PDU_INFORM(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_INFORM

class ASN1_SNMP_PDU_TRAPv2(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv2

class ASN1_SNMP_PDU_REPORT(ASN1_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_REPORT


# RFC1448
class ASN1_Class_SNMP_VARBIND(ASN1_Class_UNIVERSAL):
    name="SNMP VarBind Exceptions"
    EXC_NOSUCHOBJECT = 0x80
    EXC_NOSUCHINSTANCE = 0x81
    EXC_ENDOFMIBVIEW = 0x82

class ASN1_SNMP_EXC_NOSUCHOBJECT(ASN1_NULL):
    tag = ASN1_Class_SNMP_VARBIND.EXC_NOSUCHOBJECT

class ASN1_SNMP_EXC_NOSUCHINSTANCE(ASN1_NULL):
    tag = ASN1_Class_SNMP_VARBIND.EXC_NOSUCHINSTANCE

class ASN1_SNMP_EXC_ENDOFMIBVIEW(ASN1_NULL):
    tag = ASN1_Class_SNMP_VARBIND.EXC_ENDOFMIBVIEW


######[ BER codecs ]#######

class BERcodec_SNMP_PDU_GET(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_GET

class BERcodec_SNMP_PDU_NEXT(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_NEXT

class BERcodec_SNMP_PDU_RESPONSE(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_RESPONSE

class BERcodec_SNMP_PDU_SET(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_SET

class BERcodec_SNMP_PDU_TRAPv1(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv1

class BERcodec_SNMP_PDU_BULK(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_BULK

class BERcodec_SNMP_PDU_INFORM(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_INFORM

class BERcodec_SNMP_PDU_TRAPv2(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_TRAPv2

class BERcodec_SNMP_PDU_REPORT(BERcodec_SEQUENCE):
    tag = ASN1_Class_SNMP.PDU_REPORT


class BERcodec_SNMP_EXC_NOSUCHOBJECT(BERcodec_NULL):
    tag = ASN1_Class_SNMP_VARBIND.EXC_NOSUCHOBJECT

class BERcodec_SNMP_EXC_NOSUCHINSTANCE(BERcodec_NULL):
    tag = ASN1_Class_SNMP_VARBIND.EXC_NOSUCHINSTANCE

class BERcodec_SNMP_EXC_ENDOFMIBVIEW(BERcodec_NULL):
    tag = ASN1_Class_SNMP_VARBIND.EXC_ENDOFMIBVIEW



######[ ASN1 fields ]######

class ASN1F_SNMP_PDU_GET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_GET

class ASN1F_SNMP_PDU_NEXT(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_NEXT

class ASN1F_SNMP_PDU_RESPONSE(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_RESPONSE

class ASN1F_SNMP_PDU_SET(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_SET

class ASN1F_SNMP_PDU_TRAPv1(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_TRAPv1

class ASN1F_SNMP_PDU_BULK(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_BULK

class ASN1F_SNMP_PDU_INFORM(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_INFORM

class ASN1F_SNMP_PDU_TRAPv2(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_TRAPv2

class ASN1F_SNMP_PDU_REPORT(ASN1F_SEQUENCE):
    ASN1_tag = ASN1_Class_SNMP.PDU_REPORT


class ASN1F_varbind(ASN1F_field):
    def m2i(self, pkt, x):
        tag = self.ASN1_tag
        for exc in [ASN1_Class_SNMP_VARBIND.EXC_NOSUCHOBJECT,
                    ASN1_Class_SNMP_VARBIND.EXC_NOSUCHINSTANCE,
                    ASN1_Class_SNMP_VARBIND.EXC_ENDOFMIBVIEW]:
            if ord(x[0]) == exc:
                tag = exc
        return tag.get_codec(pkt.ASN1_codec).safedec(x, context=self.context)



######[ SNMP Packet ]######

# RFC3416
SNMP_error = { 0: "no_error",
               1: "too_big",
               2: "no_such_name",
               3: "bad_value",
               4: "read_only",
               5: "generic_error",
               6: "no_access",
               7: "wrong_type",
               8: "wrong_length",
               9: "wrong_encoding",
              10: "wrong_value",
              11: "no_creation",
              12: "inconsistent_value",
              13: "ressource_unavailable",
              14: "commit_failed",
              15: "undo_failed",
              16: "authorization_error",
              17: "not_writable",
              18: "inconsistent_name",
               }

# RFC1157
SNMP_trap_types = { 0: "cold_start",
                    1: "warm_start",
                    2: "link_down",
                    3: "link_up",
                    4: "auth_failure",
                    5: "egp_neigh_loss",
                    6: "enterprise_specific",
                    }

# http://www.iana.org/assignments/snmp-number-spaces/snmp-number-spaces.xml
SNMP_security_models = { 0: "reserved_any",
                         1: "reserved_v1",
                         2: "reserved_v2c",
                         3: "usm",
                         4: "tsm",
                         }

class SNMPvarbind(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE( ASN1F_OID("oid","1.3"),
                                ASN1F_varbind("value",ASN1_NULL(0))
                                )


class SNMPget(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_GET( ASN1F_INTEGER("id",0),
                                    ASN1F_enum_INTEGER("error",0, SNMP_error),
                                    ASN1F_INTEGER("error_index",0),
                                    ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                    )

class SNMPnext(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_NEXT( ASN1F_INTEGER("id",0),
                                     ASN1F_enum_INTEGER("error",0, SNMP_error),
                                     ASN1F_INTEGER("error_index",0),
                                     ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                     )

class SNMPresponse(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_RESPONSE( ASN1F_INTEGER("id",0),
                                         ASN1F_enum_INTEGER("error",0, SNMP_error),
                                         ASN1F_INTEGER("error_index",0),
                                         ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                         )

class SNMPset(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_SET( ASN1F_INTEGER("id",0),
                                    ASN1F_enum_INTEGER("error",0, SNMP_error),
                                    ASN1F_INTEGER("error_index",0),
                                    ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                    )
    
class SNMPtrapv1(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_TRAPv1( ASN1F_OID("enterprise", "1.3"),
                                       ASN1F_IPADDRESS("agent_addr","0.0.0.0"),
                                       ASN1F_enum_INTEGER("generic_trap", 0, SNMP_trap_types),
                                       ASN1F_INTEGER("specific_trap", 0),
                                       ASN1F_TIME_TICKS("time_stamp", IntAutoTime()),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )

class SNMPbulk(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_BULK( ASN1F_INTEGER("id",0),
                                     ASN1F_INTEGER("non_repeaters",0),
                                     ASN1F_INTEGER("max_repetitions",0),
                                     ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                     )
    
class SNMPinform(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_INFORM( ASN1F_INTEGER("id",0),
                                       ASN1F_enum_INTEGER("error",0, SNMP_error),
                                       ASN1F_INTEGER("error_index",0),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )
    
class SNMPtrapv2(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_TRAPv2( ASN1F_INTEGER("id",0),
                                       ASN1F_enum_INTEGER("error",0, SNMP_error),
                                       ASN1F_INTEGER("error_index",0),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )
    
class SNMPreport(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SNMP_PDU_REPORT( ASN1F_INTEGER("id",0),
                                       ASN1F_enum_INTEGER("error",0, SNMP_error),
                                       ASN1F_INTEGER("error_index",0),
                                       ASN1F_SEQUENCE_OF("varbindlist", [], SNMPvarbind)
                                       )
    

class SNMP(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 1, {0:"v1", 1:"v2c", 2:"v2", 3:"v3"}),
        ASN1F_STRING("community","public"),
        ASN1F_CHOICE("PDU", SNMPget(),
                     SNMPget, SNMPnext, SNMPresponse, SNMPset,
                     SNMPtrapv1, SNMPbulk, SNMPinform, SNMPtrapv2)
        )
    overload_fields = {UDP: {"sport": 161, "dport": 161 }}
    def answers(self, other):
        return ( isinstance(self.PDU, SNMPresponse)    and
                 ( isinstance(other.PDU, SNMPget) or
                   isinstance(other.PDU, SNMPnext) or
                   isinstance(other.PDU, SNMPset)    ) and
                 self.PDU.id == other.PDU.id )


class ASN1F_SNMP_SECURITY(ASN1F_PACKET):
    ASN1_tag = ASN1_Class_UNIVERSAL.STRING
    def __init__(self, name, default):
        ASN1F_field.__init__(self, name, default)
        self.cls = Raw
    def i2m(self, pkt, x):
        x = ASN1F_PACKET.i2m(self, pkt, x)
        return ASN1F_field.i2m(self, pkt, x)
    def m2i(self, pkt, x):
        if pkt.security_model == 3:
            self.cls = SNMPsecurityUSM
#        elif pkt.security_model == 4:
#            self.cls = SNMPsecurityTSM
        else:
            self.cls = Raw
        x,remain = ASN1F_field.m2i(self, pkt, x)
        i,r =  ASN1F_PACKET.m2i(self, pkt, x.val)
        if r:
            i.payload = Raw(r)
        return i,remain
    
class SNMPsecurityUSM(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING("auth_engine_id", ""),
        ASN1F_INTEGER("auth_engine_boots", 0),
        ASN1F_INTEGER("auth_engine_time", 0),
        ASN1F_STRING("user_name",""),
        ASN1F_STRING("authentication",""),
        ASN1F_STRING("privacy","")
        )
    
class SNMPscopedPDU(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_STRING("context_engine_id", ""),
        ASN1F_STRING("context_name",""),
        ASN1F_CHOICE("PDU", SNMPget(),
                     SNMPget, SNMPnext, SNMPresponse, SNMPset,
                     SNMPtrapv1, SNMPbulk, SNMPinform, SNMPtrapv2,
                     SNMPreport)
        )
    def answers(self, other):
        return ( isinstance(self.PDU, SNMPresponse or 
                 isinstance(self.PDU, SNMPreport) )    and
                 ( isinstance(other.PDU, SNMPget) or
                   isinstance(other.PDU, SNMPnext) or
                   isinstance(other.PDU, SNMPbulk) or
                   isinstance(other.PDU, SNMPset) or
                   isinstance(other.PDU, SNMPreport)    ) and
                 self.PDU.id == other.PDU.id )
    def extract_padding(self, p):
        return "",p
    
class SNMPencryptedPDU(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_STRING("encrypted_pdu","")
    
class SNMPv3(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
        ASN1F_enum_INTEGER("version", 3, {0:"v1", 1:"v2c", 2:"v2", 3:"v3"}),
        ASN1F_SEQUENCE(ASN1F_INTEGER("id", 0),
                       ASN1F_INTEGER("max_size", 1500),
                       ASN1F_STRING("flags", None),
                       ASN1F_enum_INTEGER("security_model", 3, SNMP_security_models)),
        ASN1F_SNMP_SECURITY("security", SNMPsecurityUSM()),
        ASN1F_CHOICE("data", SNMPscopedPDU(),
                     SNMPscopedPDU, SNMPencryptedPDU)
        )
    overload_fields = {UDP: {"sport": 161, "dport": 161 }}
    def post_build(self, p, pay):
        if self.flags is None:
            flags = 0
            if self.security_model == 3:
                if self.security.authentication != "":
                    flags += 0x01
                if self.security.privacy != "":
                    flags += 0x02
            s = self.copy()
            s.flags = struct.pack("B",flags)
            return s.build()
        return p+pay


def _snmp_dispatcher(x, *args, **kargs):
    cls = Raw
    try:
        ver = BERcodec_SEQUENCE.safedec(x)[0][0]
        if ver >= 3:
            cls = SNMPv3
        else:
            cls = SNMP
        pkt = cls(x, *args, **kargs)
    except:
        pkt = Raw(x)
    return pkt

bind_bottom_up(UDP, _snmp_dispatcher, { "dport": 161 })
bind_bottom_up(UDP, _snmp_dispatcher, { "sport": 161 })
bind_bottom_up(UDP, _snmp_dispatcher, { "dport": 162 })
bind_bottom_up(UDP, _snmp_dispatcher, { "sport": 162 })



def snmpwalk(dst, oid="1", community="public"):
    try:
        while 1:
            r = sr1(IP(dst=dst)/UDP(sport=RandShort())/SNMP(community=community, PDU=SNMPnext(varbindlist=[SNMPvarbind(oid=oid)])),timeout=2, chainCC=1, verbose=0, retry=2)
            if ICMP in r:
                print repr(r)
                break
            if r is None:
                print "No answers"
                break
            print "%-40s: %r" % (r[SNMPvarbind].oid.val,r[SNMPvarbind].value)
            oid = r[SNMPvarbind].oid
            
    except KeyboardInterrupt:
        pass


def __gethashfunc(protocol):
    if protocol == "MD5": # RFC3414
        return hashlib.md5
    elif protocol == "SHA": # RFC3414
        return hashlib.sha1
    else:
        raise Scapy_Exception("Unknown protocol %r" % protocol)

def snmpgeneratekey(password, engine, protocol):
    hash_func = __gethashfunc(protocol)
    
    key = hash_func((password*(2**20/len(password)+1))[:2**20]).digest()
    return hash_func(key+engine+key).digest()

def snmphash(pkt, password, protocol):
    pkt = pkt.copy()
    snmpv3 = SNMPv3(str(pkt["SNMPv3"]))
    pkt["SNMPv3"] = snmpv3
    
    if snmpv3.security_model != 3:
        raise Scapy_Exception("Unsupported security model")
    
    hash_func = __gethashfunc(protocol)
    
    auth_asn1 = snmpv3.security.authentication
    
    engine = snmpv3.security.auth_engine_id.val
    key = snmpgeneratekey(password, engine, protocol)
    
    snmpv3.security.authentication = ASN1_STRING("\x00"*12)
    
    ext_key = key+"\x00"*(64-len(key))
    k1 = "".join(chr(ord(e)^ord(i)) for e,i in zip(ext_key,"\x36"*64))
    k2 = "".join(chr(ord(e)^ord(o)) for e,o in zip(ext_key,"\x5C"*64))
    hash1 = hash_func(k1+str(snmpv3)).digest()
    hash2 = hash_func(k2+hash1).digest()
    mac = hash2[:12]
    
#    snmpv3.security.authentication = auth_asn1
    
    return mac

def snmpauthenticate(pkt, password, protocol):
    pkt = pkt.copy()
    snmpv3 = SNMPv3(str(pkt["SNMPv3"]))
    pkt["SNMPv3"] = snmpv3
    
    auth = snmpv3.security.authentication.val
    if len(auth) != 12:
        raise Scapy_Exception("Invalid authentication parameter")
    
    return snmphash(pkt, password, protocol) == auth

def snmpsetauth(pkt, password, protocol):
    pkt = pkt.copy()
    snmpv3 = SNMPv3(str(pkt["SNMPv3"]))
    pkt["SNMPv3"] = snmpv3
    
    if snmpv3.security_model != 3:
        raise Scapy_Exception("Unsupported security model")
    
    if snmpv3.flags is None:
        snmpv3.flags = ASN1_STRING("\x01")
    if "security" not in snmpv3.fields:
        snmpv3.security = SNMPsecurityUSM() #XXX: can't set field on default packet
    snmpv3.security.authentication = snmphash(pkt, password, protocol)
    
    return pkt

def snmpdecrypt(pkt, password, protocol, hash_protocol):
    pkt = pkt.copy()
    snmpv3 = SNMPv3(str(pkt["SNMPv3"]))
    pkt["SNMPv3"] = snmpv3
    
    if snmpv3.security_model != 3:
        raise Scapy_Exception("Unsupported security model")
    
    priv = snmpv3.security.privacy.val
    if len(priv) != 8:
        raise Scapy_Exception("Invalid privacy parameter")
    data = snmpv3.data.encrypted_pdu.val
    engine = snmpv3.security.auth_engine_id.val
    engine_boots = struct.pack(">l", snmpv3.security.auth_engine_boots.val)
    engine_time = struct.pack(">l", snmpv3.security.auth_engine_time.val)
    key = snmpgeneratekey(password, engine, hash_protocol)
    
    if protocol == "DES": # RFC3414
        iv = "".join(chr(ord(s)^ord(p)) for s,p in zip(key[8:16], priv))
        data = DES.new(key[:8], DES.MODE_CBC, iv).decrypt(data)
    elif protocol == "AES": # RFC3826
        iv = engine_boots + engine_time + priv
        pad_len = 16-len(data)%16
        data += "\x00"*pad_len
        data = AES.new(key[:16], AES.MODE_CFB, iv, segment_size=128).decrypt(data)
    else:
        raise Scapy_Exception("Unknown protocol %r" % protocol)
    
    snmpv3.data = SNMPscopedPDU(data)
    if snmpv3.data.payload:
        del(snmpv3.data.payload)
    snmpv3.flags = None
    snmpv3.security.privacy = ASN1_STRING("")
    snmpv3.security.authentication = ASN1_STRING(snmphash(pkt, password, hash_protocol))
    return pkt

def snmpencrypt(pkt, password, priv, protocol, hash_protocol):
    pkt = pkt.copy()
    snmpv3 = SNMPv3(str(pkt["SNMPv3"]))
    pkt["SNMPv3"] = snmpv3
    
    if snmpv3.security_model != 3:
        raise Scapy_Exception("Unsupported security model")
    
    if not isinstance(priv, basestring):
        if isinstance(priv, ASN1_STRING):
            priv = priv.val
        else:
            try:
                priv = struct.pack(">q", priv)
            except:
                priv = str(priv)
    
    data = str(snmpv3.data)
    engine = snmpv3.security.auth_engine_id.val
    engine_boots = struct.pack(">l", snmpv3.security.auth_engine_boots.val)
    engine_time = struct.pack(">l", snmpv3.security.auth_engine_time.val)
    key = snmpgeneratekey(password, engine, hash_protocol)
    
    if protocol == "DES": # RFC3414
        iv = "".join(chr(ord(s)^ord(p)) for s,p in zip(key[8:16], priv))
        pad_len = 8-len(data)%8
        data += "\x00"*pad_len
        data = DES.new(key[:8], DES.MODE_CBC, iv).encrypt(data)
    elif protocol == "AES": # RFC3826
        iv = engine_boots + engine_time + priv
        pad_len = 16-len(data)%16
        data += "\x00"*pad_len
        data = AES.new(key[:16], AES.MODE_CFB, iv, segment_size=128).encrypt(data)
        data = data[:-pad_len]
    else:
        raise Scapy_Exception("Unknown protocol %r" % protocol)
    
    snmpv3.data = SNMPencryptedPDU(encrypted_pdu=ASN1_STRING(data))
    snmpv3.flags = None
    snmpv3.security.privacy = ASN1_STRING(priv)
    snmpv3.security.authentication = ASN1_STRING(snmphash(pkt, password, hash_protocol))
    return pkt
