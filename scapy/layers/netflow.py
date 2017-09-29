## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## Netflow v5 (C) Ryan Speers <ryan@riverloopsecurity.com>
## This program is published under a GPLv2 license

"""
Cisco NetFlow protocol
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP

class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]

class NetflowFileHeader(Packet):
    name = "Netflow File Header"
    fields_desc = [ XShortField("magic", 0xCF10),
                    ByteField("endian", 1),
                    ByteField("version", 5),
                    LEFieldLenField("hdr_len", 0, length_of="tlvs"),
                    StrLenField("tlvs", "", length_from=lambda pkt: pkt.hdr_len-8) ]
    read_len = 8 #minimal length to read from a file, in order to get to the end of the fixed length header
    #TODO make hdr_len computed to support TLVs in the header
    #TODO parse TLVs as nested fields

# Cisco Netflow Protocol version 1    
class NetflowHeaderV1(Packet):
    name = "Netflow Header V1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0) ]


class NetflowRecordV1(Packet):
    name = "Netflow Record"
    fields_desc = [ IPField("ipsrc", "0.0.0.0"),
                    IPField("ipdst", "0.0.0.0"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("inputIfIndex", 0),
                    ShortField("outpuIfIndex", 0),
                    IntField("dpkts", 0),
                    IntField("dbytes", 0),
                    IntField("starttime", 0),
                    IntField("endtime", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ShortField("padding", 0),
                    ByteField("proto", 0),
                    ByteField("tos", 0),
                    IntField("padding1", 0),
                    IntField("padding2", 0) ]

# Cisco Netflow Protocol version 5
class NetflowRecordV5(Packet):
    '''Big-endian (network byte order) version. Not tested and fields likely out of order!'''
    name = "Netflow Record v5"
    fields_desc = [ IntField("secs", 0),            #seconds since epoch
                    IntField("nsecs", 0),           #nano-seconds since epoch
                    IntField("r_ms", 0),            #ms since the router booted
                    IPField("exp", "0.0.0.0"),      #ipv4 address of exporter
                    IPField("src", "0.0.0.0"),      #ipv4 address of flow source
                    IPField("dst", "0.0.0.0"),      #ipv4 address of flow dest
                    IPField("nh", "0.0.0.0"),       #ipv4 address of next hop
                    ShortField("in_if", 0),         #SNMP ingress interface
                    ShortField("out_if", 0),        #SNMP egress interface
                    IntField("pkts", 0),            #pkts in the flow
                    IntField("bytes", 0),           #layer 3 bytes in flow
                    IntField("srt", 0),             #start time
                    IntField("end", 0),             #end time
                    ShortField("src_p", 0),         #transport layer source port
                    ShortField("dst_p", 0),         #transport layer dest port
                    ByteField("proto", 0),          #protocol
                    ByteField("tos", 0),            #ToS byte
                    ByteField("flg", 0),            #TCP flags
                    ByteField("pad1", 0),           #padding
                    ByteField("eng_t", 0),          #netflow engine type
                    ByteField("eng_id", 0),         #netflow engine ID
                    ByteField("src_msk", 0),        #source addr mask bits
                    ByteField("dst_msk", 0),        #dest addr mask bits
                    ShortField("src_as", 0),        #source AS
                    ShortField("dst_as", 0)  ]      #destination AS

class LENetflowRecordV5(Packet):
    '''Little-endian version for reading from a Netflow file.'''
    name = "Netflow Record v5 (LE)"
    fields_desc = [ LEIntField("secs", 0),            #seconds since epoch
                    LEIntField("nsecs", 0),           #nano-seconds since epoch
                    LEIntField("r_ms", 0),            #ms since the router booted
                    LEIPField("exp", "0.0.0.0"),      #ipv4 address of exporter
                    LEIPField("src", "0.0.0.0"),      #ipv4 address of flow source
                    LEIPField("dst", "0.0.0.0"),      #ipv4 address of flow dest
                    LEIPField("nh", "0.0.0.0"),       #ipv4 address of next hop
                    LEShortField("in_if", 0),         #SNMP ingress interface
                    LEShortField("out_if", 0),        #SNMP egress interface
                    LEIntField("pkts", 0),            #pkts in the flow
                    LEIntField("bytes", 0),           #layer 3 bytes in flow
                    LEIntField("srt", 0),             #start time
                    LEIntField("end", 0),             #end time
                    LEShortField("src_p", 0),         #transport layer source port
                    LEShortField("dst_p", 0),         #transport layer dest port
                    ByteField("proto", 0),            #protocol
                    ByteField("tos", 0),              #ToS byte
                    ByteField("flg", 0),              #TCP flags
                    ByteField("pad1", 0),             #padding
                    ByteField("eng_t", 0),            #netflow engine type
                    ByteField("eng_id", 0),           #netflow engine ID
                    ByteField("src_msk", 0),          #source addr mask bits
                    ByteField("dst_msk", 0),          #dest addr mask bits
                    LEShortField("src_as", 0),        #source AS
                    LEShortField("dst_as", 0)  ]      #destination AS

bind_layers( UDP,             NetflowHeader,   sport=9995)
bind_layers( UDP,             NetflowHeader,   dport=9995)
bind_layers( UDP,             NetflowHeader,   sport=9555)
bind_layers( UDP,             NetflowHeader,   dport=9555)
bind_layers( UDP,             NetflowHeader,   sport=2055)
bind_layers( UDP,             NetflowHeader,   dport=2055)
bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1, )

#Uncomment after testing the NetflowRecordV5 on network traffic:
#bind_layers( NetflowHeader,   NetflowRecordV5, version=5)

