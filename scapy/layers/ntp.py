## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
NTP (Network Time Protocol).
"""

import time
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP


# seconds between 01-01-1900 and 01-01-1970
_NTP_BASETIME = 2208988800

class TimeStampField(FixedPointField):
    def __init__(self, name, default):
        FixedPointField.__init__(self, name, default, 64, 32)

    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        val = float(self.i2h(pkt,val))
        if val < _NTP_BASETIME or val-_NTP_BASETIME >= 2**31:
            return repr(val)
        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(val-_NTP_BASETIME))

    def any2i(self, pkt, val):
        if type(val) is str:
            return int(time.mktime(time.strptime(val))) + _NTP_BASETIME + 3600 # XXX
        return FixedPointField.any2i(self,pkt,val)
    
    def i2m(self, pkt, val):
        if val is None:
            val = FixedPointField.any2i(self, pkt, time.time()+_NTP_BASETIME)
        return FixedPointField.i2m(self, pkt, val)
        


class NTP(Packet):
    # RFC 1769
    name = "NTP"
    fields_desc = [ 
        BitEnumField('leap', 0, 2,
                     { 0: 'nowarning',
                       1: 'longminute',
                       2: 'shortminute',
                       3: 'notsync'}),
        BitField('version', 3, 3),
        BitEnumField('mode', 3, 3,
                     { 0: 'reserved',
                       1: 'sym_active',
                       2: 'sym_passive',
                       3: 'client',
                       4: 'server',
                       5: 'broadcast',
                       6: 'control',
                       7: 'private'}),
        ByteField('stratum', 0),
        SignedByteField('poll', 10),
        SignedByteField('precision', -6),
        FixedPointField('delay', 0, size=32, frac_bits=16),
        FixedPointField('dispersion', 0, size=32, frac_bits=16),
        ConditionalField(StrFixedLenField('id', "ATOM", 4),
                         lambda pkt:pkt.stratum not in range(2,16)),
        ConditionalField(IPField('addr', "127.0.0.1"),
                         lambda pkt:pkt.stratum in range(2,16)),
        TimeStampField('ref', 0),
        TimeStampField('orig', None),  # None means current time
        TimeStampField('recv', 0),
        TimeStampField('sent', None) 
        ]
    def mysummary(self):
        return self.sprintf("NTP v%ir,NTP.version%, %NTP.mode%")


bind_layers( UDP,           NTP,           dport=123, sport=123)
