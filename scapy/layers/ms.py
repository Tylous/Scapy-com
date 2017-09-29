## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Common Microsoft data structures.
"""

import datetime,binascii
from scapy.fields import *
from scapy.packet import *


enum_BOOLEAN = {0:"False",1:"True"}

_ACCESS_MASK_common = ["DELETE","READ_CONTROL","WRITE_DAC","WRITE_OWNER",
                       "SYNCHRONIZE","","","",
                       "ACCESS_SYSTEM_SECURITY","MAXIMUM_ALLOWED","","",
                       "GENERIC_ALL","GENERIC_EXECUTE","GENERIC_WRITE","GENERIC_READ"]

ACCESS_MASK = ["READ_DATA","WRITE_DATA","APPEND_DATA","READ_EA",
               "WRITE_EA","EXECUTE","DELETE_CHILD","READ_ATTRIBUTES",
               "WRITE_ATTRIBUTES","","","",
               "","","",""]+_ACCESS_MASK_common

ACCESS_MASK_directory = ["LIST_DIRECTORY","ADD_FILE","ADD_SUBDIRECTORY","READ_EA",
                         "WRITE_EA","TRAVERSE","DELETE_CHILD","READ_ATTRIBUTES",
                         "WRITE_ATTRIBUTES","","","",
                         "","","",""]+_ACCESS_MASK_common

FEA_flags = ["","","","",
             "","","","FILE_NEED_EA"]



class UCHAR_LenField(StrLenField):
    def __init__(self, name, default, fld=None, length_from=None):
        StrLenField.__init__(self, name, default, "utf-16-le", fld, length_from)



class FILETIME_Field(LELongField):
    epoch = datetime.datetime(1601,1,1)
    strfmt = "%a, %d %b %Y %H:%M:%S +0000"
    def __init__(self, name, default):
        #if default is None:
        #    default = 116444736000000000 # UNIX epoch
        Field.__init__(self, name, default, "<Q")
    def i2repr(self, pkt, x):
        if x is None:
            s = datetime.datetime.utcnow().strftime(self.strfmt)
            return "%s (now)" % s
        try:
            t = self.epoch+datetime.timedelta(microseconds=x/10)
            s = t.strftime(self.strfmt)
            return "%s (%d)" % (s, x)
        except: #XXX: only supports 1900 <= year < 10000
            return LELongField.i2repr(pkt, x)
    def i2m(self, pkt, x):
        if x is None:
            t = datetime.datetime.utcnow()-self.epoch
            x = ((t.days*86400+t.seconds)*1000000+t.microseconds)*10
        return x



class GUIDField(StrFixedLenField):
    def __init__(self, name, default):
        if not default:
            default = "{00000000-0000-0000-0000-000000000000}"
        StrFixedLenField.__init__(self, name, default, 16)
    def any2i(self, pkt, x):
        if len(x) == 16: # raw byte string
            x = self.m2i(pkt, x)
        try:
            self.i2m(pkt, x)
        except:
            raise ValueError("Invalid GUID %r" % x)
        return x
    def i2m(self, pkt, x):
        if not x:
            return "\x00"*16
        x = [binascii.a2b_hex(s) for s in
             str(x).lstrip("{").rstrip("}").split("-")]
        if len(x) != 5:
            raise
        return "".join([s[::-1] for s in x[:3]]+x[3:])
    def m2i(self, pkt, x):
        x = [x[0:4][::-1],x[4:6][::-1],x[6:8][::-1],x[8:10],x[10:16]]
        return "{%s}" % "-".join([binascii.b2a_hex(s) for s in x])
    def randval(self):
        return RandGUID()


class RandGUID(RandField): #XXX: could be RandUUID?
#    def __init__(self, template="{*-*-*-*-*}"):
#        self.template = template #TODO: like RandMAC, RandIP6, etc.
    def _fix(self):
        return "{%s}" % "-".join([binascii.b2a_hex(str(RandBin(l)))
                                  for l in [4,2,2,2,6]])



class SIDField(StrField):
    def __init__(self, name, default):
        StrField.__init__(self, name, default)
    def i2m(self, pkt, i):
        if not i:
            return ""
        x = i.split("-")
        if len(x) < 4 or x[0] != "S":
            raise ValueError("Invalid SID %r" % x)
        m = ""
        m += struct.pack("B", int(x[1]))
        m += struct.pack("B", len(x)-3)
        m += "\x00"*5 + struct.pack("B", int(x[2])) #XXX: verify this?
        for a in x[3:]:
            m += struct.pack("<I", int(a))
        return m
    def m2i(self, pkt, m):
        x = ["S"]
        x.append(str(ord(m[0])))
        x.append(str(ord(m[7])))
        m = m[8:]
        while m:
            x.append(str(struct.unpack("<I", m[0:4])[0]))
            m = m[4:]
        i = "-".join(x)
        return i
    def getfield(self, pkt, s):
        if len(s) < 12:
            return s,""
        r = (ord(s[1])*4)+8
        i = self.m2i(pkt, s[:r])
        return s[r:],i


class SID(Packet):
    name = "Security Identifier (SID) [MS-DTYP]"
    fields_desc = [SIDField("SID","S-1-0-0")]
    def extract_padding(self, p):
        return "",p



ace_types = {0x00: "ACCESS_ALLOWED",
             0x01: "ACCESS_DENIED",
             0x02: "SYSTEM_AUDIT",
             0x03: "SYSTEM_ALARM",                   # reserved
             0x04: "ACCESS_ALLOWED_COMPOUND",        # reserved
             0x05: "ACCESS_ALLOWED_OBJECT",
             0x06: "ACCESS_DENIED_OBJECT",
             0x07: "SYSTEM_AUDIT_OBJECT",
             0x08: "SYSTEM_ALARM_OBJECT",            # reserved
             0x09: "ACCESS_ALLOWED_CALLBACK",
             0x0A: "ACCESS_DENIED_CALLBACK",
             0x0B: "ACCESS_ALLOWED_CALLBACK_OBJECT",
             0x0C: "ACCESS_DENIED_CALLBACK_OBJECT",
             0x0D: "SYSTEM_AUDIT_CALLBACK",
             0x0E: "SYSTEM_ALARM_CALLBACK",          # reserved
             0x0F: "SYSTEM_AUDIT_CALLBACK_OBJECT",
             0x10: "SYSTEM_ALARM_CALLBACK_OBJECT",   # reserved
             0x11: "SYSTEM_MANDATORY_LABEL" }

ace_flags_object_Mask = ["RIGHT_DS_CREATE_CHILD","RIGHT_DS_DELETE_CHILD","","RIGHT_DS_SELF",
                         "RIGHT_DS_READ_PROP","RIGHT_DS_WRITE_PROP","","",
                         "RIGHT_DS_CONTROL_ACCESS","","","",
                         "","","",""]+_ACCESS_MASK_common

ace_flags_object_Flags = ["OBJECT_TYPE_PRESENT","INHERITED_OBJECT_TYPE_PRESENT"]

ace_flags_sml_Mask = ["NO_WRITE_UP","NO_READ_UP","NO_EXECUTE_UP","",
                      "","","","",
                      "","","","",
                      "","","",""]+_ACCESS_MASK_common


class _ACE_HDR(Packet):
    name = "Abstract ACE Header"
    fields_desc = [ByteEnumField("AceType",0xFF,ace_types),
                   LEFlagsField("AceFlags",0,8,["OI","CI","NP","IO",
                                                "ID","","SA","FA"]),
                   LEShortField("AceSize",None)]


class ACE(Packet):
    name = "Access Control Entry (ACE) [MS-DTYP]"
    fields_desc = [_ACE_HDR,
                   LEFlagsField("Mask",0,32,ACCESS_MASK),
                   SIDField("SID","S-1-0-0")]
    def post_build(self, p, pay):
        p += pay
        if self.AceSize is None:
            l = len(p)
            p = p[:2]+chr(l&0xff)+chr((l>>8)&0xff)+p[4:]
        return p
    def extract_padding(self, p):
        return "",p
    registered_ace = {}
    @classmethod
    def register_variant(cls):
        cls.registered_ace[cls.AceType.default] = cls
    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            acetype = ord(pkt[0])
            if acetype in cls.registered_ace:
                return cls.registered_ace[acetype]
        return cls

class ACE_ACCESS_ALLOWED(ACE):
    name = "ACE - ACCESS_ALLOWED_ACE [MS-DTYP]"
    AceType = 0x00

class ACE_ACCESS_DENIED(ACE):
    name = "ACE - ACCESS_DENIED_ACE [MS-DTYP]"
    AceType = 0x01

class ACE_SYSTEM_AUDIT(ACE):
    name = "ACE - SYSTEM_AUDIT_ACE [MS-DTYP]"
    AceType = 0x02

class ACE_ACCESS_ALLOWED_OBJECT(ACE):
    name = "ACE - ACCESS_ALLOWED_OBJECT_ACE [MS-DTYP]"
    AceType = 0x05
    fields_desc = [_ACE_HDR,
                   LEFlagsField("Mask",0,32,ace_flags_object_Mask),
                   LEFlagsField("Flags",0,32,ace_flags_object_Flags),
                   GUIDField("ObjectType",""),
                   GUIDField("InheritedObjectType",""),
                   SIDField("SID","S-1-0-0")]

class ACE_ACCESS_DENIED_OBJECT(ACE_ACCESS_ALLOWED_OBJECT):
    name = "ACE - ACCESS_DENIED_OBJECT_ACE [MS-DTYP]"
    AceType = 0x06

class ACE_SYSTEM_AUDIT_OBJECT(ACE_ACCESS_ALLOWED_OBJECT):
    name = "ACE - SYSTEM_AUDIT_OBJECT_ACE [MS-DTYP]"
    AceType = 0x07

class ACE_ACCESS_ALLOWED_CALLBACK(ACE):
    name = "ACE - ACCESS_ALLOWED_CALLBACK_ACE [MS-DTYP]"
    AceType = 0x09
    fields_desc = [ACE,
                   StrLenField("ApplicationData","",
                               length_from=lambda pkt:pkt.AceSize-8-pkt.getfieldlen("SID"))]

class ACE_ACCESS_DENIED_CALLBACK(ACE_ACCESS_ALLOWED_CALLBACK):
    name = "ACE - ACCESS_DENIED_CALLBACK_ACE [MS-DTYP]"
    AceType = 0x0A

class ACE_ACCESS_ALLOWED_CALLBACK_OBJECT(ACE):
    name = "ACE - ACCESS_ALLOWED_CALLBACK_OBJECT_ACE [MS-DTYP]"
    AceType = 0x0B
    fields_desc = [ACE_ACCESS_ALLOWED_OBJECT,
                   StrLenField("ApplicationData","",
                               length_from=lambda pkt:pkt.AceSize-8-pkt.getfieldlen("SID"))]

class ACE_ACCESS_DENIED_CALLBACK_OBJECT(ACE_ACCESS_ALLOWED_CALLBACK_OBJECT):
    name = "ACE - ACCESS_DENIED_CALLBACK_OBJECT_ACE [MS-DTYP]"
    AceType = 0x0C

class ACE_SYSTEM_AUDIT_CALLBACK(ACE_ACCESS_ALLOWED_CALLBACK):
    name = "ACE - SYSTEM_AUDIT_CALLBACK_ACE [MS-DTYP]"
    AceType = 0x0D

class ACE_SYSTEM_AUDIT_CALLBACK_OBJECT(ACE_ACCESS_ALLOWED_CALLBACK_OBJECT):
    name = "ACE - SYSTEM_AUDIT_CALLBACK_OBJECT_ACE [MS-DTYP]"
    AceType = 0x0F

class ACE_SYSTEM_MANDATORY_LABEL(ACE):
    name = "ACE - SYSTEM_MANDATORY_LABEL_ACE [MS-DTYP]"
    AceType = 0x11
    fields_desc = [_ACE_HDR,
                   LEFlagsField("Mask",0,32,ace_flags_sml_Mask),
                   SIDField("SID","S-1-0-0")]


class ACL(Packet):
    name = "Access Control List (ACL) [MS-DTYP]"
    fields_desc = [ByteEnumField("AclRevision",2,{2:"ACL_REVISION",4:"ACL_REVISION_DS"}),
                   ByteField("Sbz1",0),
                   FieldLenField("AclSize",None,length_of="ACEs",fmt="<H",
                                 adjust=lambda pkt,x:x+8),
                   FieldLenField("AceCount",None,count_of="ACEs",fmt="<H"),
                   LEShortField("Sbz2",0),
                   PacketListField("ACEs",[],ACE,count_from=lambda pkt:pkt.AceCount)]
    def extract_padding(self, p):
        return "",p

class SACL(ACL):
    name = "System Access Control List (SACL) [MS-DTYP]"

class DACL(ACL):
    name = "Discretionary Access Control List (DACL) [MS-DTYP]"


class SECURITY_DESCRIPTOR(Packet):
    name = "SECURITY_DESCRIPTOR [MS-DTYP]"
    fields_desc = [ByteField("Revision",1),
                   ByteField("Sbz1",0),
                   LEFlagsField("Control",0x8000,16,["OD","GD","DP","DD",
                                                     "SP","SD","SS","DT",
                                                     "DC","SC","DI","SI",
                                                     "PD","PS","RM","SR"]),
                   LEIntField("OffsetOwner",None),
                   LEIntField("OffsetGroup",None),
                   LEIntField("OffsetSacl",None),
                   LEIntField("OffsetDacl",None),
                   OffsetPacketListField("Data",[],20,[("OffsetOwner",SID),
                                                       ("OffsetGroup",SID),
                                                       ("OffsetSacl",SACL),
                                                       ("OffsetDacl",DACL)])]
    def post_build(self, p, pay):
        off = 20
        get_owner = self.OffsetOwner is None
        get_group = self.OffsetGroup is None
        get_sacl = self.OffsetSacl is None
        get_dacl = self.OffsetDacl is None
        for d in self.Data:
            if type(d) is SID: # assumes owner comes before group if both None
                if get_owner and off != self.OffsetGroup:
                    p = p[:4]+struct.pack("<I",off)+p[8:]
                    get_owner = False
                elif get_group and off != self.OffsetOwner:
                    p = p[:8]+struct.pack("<I",off)+p[12:]
                    get_group = False
            elif get_sacl and type(d) is SACL:
                p = p[:12]+struct.pack("<I",off)+p[16:]
                get_sacl = False
            elif get_dacl and type(d) is DACL:
                p = p[:16]+struct.pack("<I",off)+p[20:]
                get_dacl = False
            off += len(d)
        p += pay
        return p



class FILE_FULL_EA_INFORMATION(Packet):
    name = "FILE_FULL_EA_INFORMATION [MS-FSCC]"
    fields_desc = [LEIntField("NextEntryOffset",None),
                   LEFlagsField("Flags",0,8,FEA_flags),
                   FieldLenField("EaNameLength",None,length_of="EaName",fmt="B"),
                   FieldLenField("EaValueLength",None,length_of="EaValue",fmt="<H"),
                   StrLenField("EaName","",
                               length_from=lambda pkt:pkt.EaNameLength),
                   StrFixedLenField("Padding","",1),
                   StrLenField("EaValue","",
                               length_from=lambda pkt:pkt.EaValueLength)]
    def post_build(self, p, pay):
        if self.NextEntryOffset is None:
            l = len(p)
            p = p[:0]+struct.pack("<I",l)+p[4:]
        p += pay
        return p

class FILE_QUOTA_INFORMATION(Packet):
    name = "FILE_QUOTA_INFORMATION [MS-FSCC]"
    fields_desc = [FieldLenField("NextEntryOffset",None,length_of="Sid",fmt="<I",
                                 adjust=lambda pkt,x:x+40),
                   FieldLenField("SidLength",None,length_of="Sid",fmt="<I"),
                   FILETIME_Field("ChangeTime",None),
                   LESignedLongField("QuotaUsed",0),
                   LESignedLongField("QuotaThreshold",0),
                   LESignedLongField("QuotaLimit",0),
                   StrLenField("Sid","",
                               length_from=lambda pkt:pkt.SidLength)]

class FILE_GET_QUOTA_INFORMATION(Packet):
    name = "FILE_GET_QUOTA_INFORMATION [MS-FSCC]"
    fields_desc = [FieldLenField("NextEntryOffset",None,length_of="Sid",fmt="<I",
                                 adjust=lambda pkt,x:x+8),
                   FieldLenField("SidLength",None,length_of="Sid",fmt="<I"),
                   StrLenField("Sid","",
                               length_from=lambda pkt:pkt.SidLength)]

