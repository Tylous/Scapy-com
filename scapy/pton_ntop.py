## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Convert IPv6 addresses between textual representation and binary.

These functions are missing when python is compiled
without IPv6 support, on Windows for instance.
"""

import socket,struct

def inet_pton(af, addr):
    """Convert an IP address from text representation into binary form"""
    if af == socket.AF_INET:
        return utils.inet_aton(addr)
    elif af == socket.AF_INET6:
        # IPv6: The use of "::" indicates one or more groups of 16 bits of zeros.
        # We deal with this form of wildcard using a special marker. 
        JOKER = "*"
        while "::" in addr:
            addr = addr.replace("::", ":" + JOKER + ":")
        joker_pos = None 
        
        # The last part of an IPv6 address can be an IPv4 address
        ipv4_addr = None
        if "." in addr:
            ipv4_addr = addr.split(":")[-1]
           
        result = ""
        parts = addr.split(":")
        for part in parts:
            if part == JOKER:
                # Wildcard is only allowed once
                if joker_pos is None:
                    joker_pos = len(result)
                else:
                    raise Exception("Illegal syntax for IP address")
            elif part == ipv4_addr: # FIXME: Make sure IPv4 can only be last part
                # FIXME: inet_aton allows IPv4 addresses with less than 4 octets 
                result += socket.inet_aton(ipv4_addr)
            else:
                # Each part must be 16bit. Add missing zeroes before decoding. 
                try:
                    result += part.rjust(4, "0").decode("hex")
                except TypeError:
                    raise Exception("Illegal syntax for IP address")
                    
        # If there's a wildcard, fill up with zeros to reach 128bit (16 bytes) 
        if JOKER in addr:
            result = (result[:joker_pos] + "\x00" * (16 - len(result))
                      + result[joker_pos:])
    
        if len(result) != 16:
            raise Exception("Illegal syntax for IP address")
        return result 
    else:
        raise Exception("Address family not supported")


def inet_ntop(af, addr):
    """Convert an IP address from binary form into text representation"""
    if af == socket.AF_INET:
        return utils.inet_ntoa(addr)
    elif af == socket.AF_INET6:
        # IPv6 addresses have 128bits (16 bytes)
        if len(addr) != 16:
            raise Exception("Illegal syntax for IP address")
        parts = []
        start = 0
        end = found = -1
        for i,left in enumerate(range(0,15,2)):
            try: 
                value = struct.unpack("!H", addr[left:left+2])[0]
                hexstr = hex(value)[2:].lstrip("0").lower()
            except TypeError:
                raise Exception("Illegal syntax for IP address")
            if hexstr:
                parts.append(hexstr)
                found = -1
            else:
                parts.append("0")
                if found == -1: # start of new run of zeros
                    found = i
                if i - found > end - start: # longest run of zeros
                    start,end = found,i
        if end - start > -1:
            for i in range(start, end+1): # clear longest run for ::
                parts[i] = ""
        result = ":".join(parts)
        while ":::" in result:
            result = result.replace(":::", "::")
        return result
    else:
        raise Exception("Address family not supported yet")        


import utils
