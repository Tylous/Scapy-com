## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
TLS Transport Layer Security RFCs 2246, 4366, 4507

Spencer McIntyre
SecureState R&D Team
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.l2 import *

# http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-3
cipher_suites = {
        0x0000:"TLS_NULL_WITH_NULL_NULL",
        0x0001:"TLS_RSA_WITH_NULL_MD5",
        0x0002:"TLS_RSA_WITH_NULL_SHA",
        0x0003:"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004:"TLS_RSA_WITH_RC4_128_MD5",
        0x0005:"TLS_RSA_WITH_RC4_128_SHA",
        0x0006:"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0007:"TLS_RSA_WITH_IDEA_CBC_SHA",
        0x0008:"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0009:"TLS_RSA_WITH_DES_CBC_SHA",
        0x000a:"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0011:"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0012:"TLS_DHE_DSS_WITH_DES_CBC_SHA",
        0x0013:"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        0x0014:"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0015:"TLS_DHE_RSA_WITH_DES_CBC_SHA",
        0x0016:"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0017:"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        0x002f:"TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0032:"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        0x0033:"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0034:"TLS_DH_anon_WITH_AES_128_CBC_SHA",
        0x0035:"TLS_RSA_WITH_AES_256_CBC_SHA",
        0x0038:"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        0x0039:"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0041:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0044:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        0x0045:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        0x0062:"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        0x0063:"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
        0x0064:"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
        0x0084:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0087:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        0x0088:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        0x0089:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        0x0096:"TLS_RSA_WITH_SEED_CBC_SHA",
        0x0099:"TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        0x009a:"TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        0x00ff:"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        0x009b:"TLS_DH_anon_WITH_SEED_CBC_SHA",
        0x009c:"TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d:"TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009e:"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009f:"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x00a0:"TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        0x00a1:"TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        0x00a2:"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        0x00a3:"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        0x00a4:"TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        0x00a5:"TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        0x00a6:"TLS_DH_anon_WITH_AES_128_GCM_SHA256",
        0x00a7:"TLS_DH_anon_WITH_AES_256_GCM_SHA384",
        0x00a8:"TLS_PSK_WITH_AES_128_GCM_SHA256",
        0x00a9:"TLS_PSK_WITH_AES_256_GCM_SHA384",
        0x00aa:"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        0x00ab:"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        0x00ac:"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
        0x00ad:"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
        0x00ae:"TLS_PSK_WITH_AES_128_CBC_SHA256",
        0x00af:"TLS_PSK_WITH_AES_256_CBC_SHA384",
        0x00b0:"TLS_PSK_WITH_NULL_SHA256",
        0x00b1:"TLS_PSK_WITH_NULL_SHA384",
        0x00b2:"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
        0x00b3:"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
        0x00b4:"TLS_DHE_PSK_WITH_NULL_SHA256",
        0x00b5:"TLS_DHE_PSK_WITH_NULL_SHA384",
        0x00b6:"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
        0x00b7:"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
        0x00b8:"TLS_RSA_PSK_WITH_NULL_SHA256",
        0x00b9:"TLS_RSA_PSK_WITH_NULL_SHA384",
        0x00ba:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bb:"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bc:"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bd:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        0x00be:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0x00bf:"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
        0x00c0:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c1:"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c2:"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c3:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c4:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        0x00c5:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
        0xc001:"TLS_ECDH_ECDSA_WITH_NULL_SHA",
        0xc002:"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        0xc003:"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xc004:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        0xc005:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        0xc006:"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        0xc007:"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        0xc008:"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xc009:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        0xc00a:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        0xc00b:"TLS_ECDH_RSA_WITH_NULL_SHA",
        0xc00c:"TLS_ECDH_RSA_WITH_RC4_128_SHA",
        0xc00d:"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc00e:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        0xc00f:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        0xc010:"TLS_ECDHE_RSA_WITH_NULL_SHA",
        0xc011:"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        0xc012:"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc013:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0xc015:"TLS_ECDH_anon_WITH_NULL_SHA",
        0xc016:"TLS_ECDH_anon_WITH_RC4_128_SHA",
        0xc017:"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
        0xc018:"TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        0xc019:"TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        0xc01a:"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        0xc01b:"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        0xc01c:"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        0xc01d:"TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        0xc01e:"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        0xc01f:"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        0xc020:"TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
        0xc021:"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        0xc022:"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        0xc023:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc024:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc025:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        0xc026:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        0xc027:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        0xc028:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        0xc029:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        0xc02a:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        0xc02b:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02c:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02d:"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02e:"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc02f:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc030:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xc031:"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        0xc032:"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        0xc033:"TLS_ECDHE_PSK_WITH_RC4_128_SHA",
        0xc034:"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
        0xc035:"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        0xc036:"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
        0xc037:"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        0xc038:"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        0xc039:"TLS_ECDHE_PSK_WITH_NULL_SHA",
        0xc03a:"TLS_ECDHE_PSK_WITH_NULL_SHA256",
        0xc03b:"TLS_ECDHE_PSK_WITH_NULL_SHA384",
        0xc03c:"TLS_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc03d:"TLS_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc03e:"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
        0xc03f:"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
        0xc040:"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc041:"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc042:"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
        0xc043:"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
        0xc044:"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc045:"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc046:"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
        0xc047:"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
        0xc048:"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
        0xc049:"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
        0xc04a:"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
        0xc04b:"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
        0xc04c:"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc04d:"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc04e:"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
        0xc04f:"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
        0xc050:"TLS_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc051:"TLS_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc052:"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc053:"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc054:"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc055:"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc056:"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
        0xc057:"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
        0xc058:"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
        0xc059:"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
        0xc05a:"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
        0xc05b:"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
        0xc05c:"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
        0xc05d:"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
        0xc05e:"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
        0xc05f:"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
        0xc060:"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc061:"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc062:"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
        0xc063:"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
        0xc064:"TLS_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc065:"TLS_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc066:"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc067:"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc068:"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc069:"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc06a:"TLS_PSK_WITH_ARIA_128_GCM_SHA256",
        0xc06b:"TLS_PSK_WITH_ARIA_256_GCM_SHA384",
        0xc06c:"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
        0xc06d:"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
        0xc06e:"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
        0xc06f:"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
        0xc070:"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
        0xc071:"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
        0xc072:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc073:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc074:"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc075:"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc076:"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc077:"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc078:"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        0xc079:"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
        0xc07a:"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc07b:"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc07c:"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc07d:"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc07e:"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc07f:"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc080:"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        0xc081:"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        0xc082:"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
        0xc083:"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
        0xc084:"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
        0xc085:"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
        0xc086:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc087:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc088:"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc089:"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc08a:"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc08b:"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc08c:"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
        0xc08d:"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
        0xc08e:"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        0xc08f:"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        0xc090:"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        0xc091:"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        0xc092:"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
        0xc093:"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
        0xc094:"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc095:"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc096:"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc097:"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc098:"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc099:"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc09a:"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
        0xc09b:"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
        0xc09c:"TLS_RSA_WITH_AES_128_CCM",
        0xc09d:"TLS_RSA_WITH_AES_256_CCM",
        0xc09e:"TLS_DHE_RSA_WITH_AES_128_CCM",
        0xc09f:"TLS_DHE_RSA_WITH_AES_256_CCM",
        0xc0a0:"TLS_RSA_WITH_AES_128_CCM_8",
        0xc0a1:"TLS_RSA_WITH_AES_256_CCM_8",
        0xc0a2:"TLS_DHE_RSA_WITH_AES_128_CCM_8",
        0xc0a3:"TLS_DHE_RSA_WITH_AES_256_CCM_8",
        0xc0a4:"TLS_PSK_WITH_AES_128_CCM",
        0xc0a5:"TLS_PSK_WITH_AES_256_CCM",
        0xc0a6:"TLS_DHE_PSK_WITH_AES_128_CCM",
        0xc0a7:"TLS_DHE_PSK_WITH_AES_256_CCM",
        0xc0a8:"TLS_PSK_WITH_AES_128_CCM_8",
        0xc0a9:"TLS_PSK_WITH_AES_256_CCM_8",
        0xc0aa:"TLS_PSK_DHE_WITH_AES_128_CCM_8",
        0xc0ab:"TLS_PSK_DHE_WITH_AES_256_CCM_8",
    }

tls_handshake_types = {
        0:"HELLO REQUEST",
        1:"CLIENT HELLO",
        2:"SERVER HELLO",
        11:"CERTIFICATE",
        12:"SERVER KEY EXCHANGE",
        13:"CERTIFICATE REQUEST",
        14:"SERVER HELLO DONE",
        15:"CERTIFICATE VERIFY",
        16:"CLIENT KEY EXCHANGE",
        20:"FINISHED"
    }
    
tls_compression_methods = {
        0:"NONE",
        1:"DEFLATE",
        64:"LZS"
    }

class TLSv1RecordLayer(Packet):
    name = "TLSv1 Record Layer"
    fields_desc = [ ByteEnumField("code", 22, {20:"CHANGE CIPHER SPEC", 21:"ALERT", 22:"HANDSHAKE", 23:"APPLICATION DATA"}),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1), 
                    FieldLenField("length", None, length_of="data", fmt="H"),
                    ConditionalField(StrLenField("data", None, length_from=lambda pkt:pkt.length), lambda pkt:pkt.code != 22),
                    ConditionalField(ByteEnumField("hs_type", 1, tls_handshake_types), lambda pkt:pkt.code == 22),
                    ConditionalField(StrLenField("data", None, length_from=lambda pkt:pkt.length - 1), lambda pkt:pkt.code == 22 and pkt.hs_type not in tls_handshake_types),
                ]
                
    def guess_payload_class(self, payload):
        if self.code != 22:
            return TLSv1RecordLayer
        elif self.hs_type in [1, 2, 11, 12, 14, 16]:
            return {1:TLSv1ClientHello, 2:TLSv1ServerHello, 11:TLSv1Certificate, 12:TLSv1KeyExchange, 14:TLSv1ServerHelloDone, 16:TLSv1KeyExchange}[self.hs_type]
        else:
            return TLSv1RecordLayer

class TLSv1ClientHello(Packet):
    name = "TLSv1 Client Hello"
    fields_desc = [ FieldThreeBytesLenField("length", 36, adjust=lambda pkt, x:pkt.session_id_length + pkt.cipher_suites_length + pkt.compression_methods_length + 36),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1),
                    
                    UTCTimeField("unix_time", None),
                    StrFixedLenField("random_bytes", 0x00, length=28),
                    
                    FieldLenField("session_id_length", None, length_of="session_id", fmt="B"),
                    ConditionalField(StrLenField("session_id", "", length_from=lambda pkt:pkt.session_id_length), lambda pkt:pkt.session_id_length),
                    
                    FieldLenField("cipher_suites_length", 2, length_of="cipher_suites", fmt="H"),
                    FieldListField("cipher_suites", [0x0000], ShortEnumField("cipher_suite", 0x0000, cipher_suites), count_from = lambda pkt:pkt.cipher_suites_length / 2),
                    
                    FieldLenField("compression_methods_length", 1, length_of="compression_methods", fmt="B"),
                    FieldListField("compression_methods", [0x00], ByteEnumField("compression_method", 0x00, tls_compression_methods), count_from = lambda pkt:pkt.compression_methods_length),
                    
                    ConditionalField(FieldLenField("extensions_length", 2, length_of="extensions", fmt="H"), lambda pkt:pkt.length > pkt.session_id_length + pkt.cipher_suites_length + pkt.compression_methods_length + 36),
                    ConditionalField(StrLenField("extensions", "", length_from=lambda pkt:pkt.extensions_length), lambda pkt:pkt.extensions_length),
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1ServerHello(Packet):
    name = "TLSv1 Server Hello"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of=lambda pkt:pkt.session_id_length + 40),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1),
                    
                    UTCTimeField("unix_time", None),
                    StrFixedLenField("random_bytes", 0x00, length=28),
                    FieldLenField("session_id_length", 0, length_of="session_id", fmt="B"),
                    ConditionalField(StrLenField("session_id", "", length_from=lambda pkt:pkt.session_id_length), lambda pkt:pkt.session_id_length),
                    ShortEnumField("cipher_suite", 0x0000, cipher_suites),
                    ByteEnumField("compression_method", 0x00, {0x00:"NONE"}),
                    
                    ConditionalField(FieldLenField("extensions_length", 0, length_of="extensions", fmt="H"), lambda pkt:pkt.length > pkt.session_id_length + 38),
                    ConditionalField(StrLenField("extensions", "", length_from=lambda pkt:pkt.extensions_length), lambda pkt:pkt.extensions_length),
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1ServerHelloDone(Packet):
    name = "TLSv1 Server Hello Done"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of="server_cert", adjust=lambda pkt,x:len(pkt.data) + 2),
                    StrLenField("data", "", length_from=lambda pkt: pkt.length)
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer

class TLSv1KeyExchange(Packet):
    name = "TLSv1 Key Exchange"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of="server_cert"),
                    StrLenField("server_cert", "", length_from=lambda pkt:pkt.length),
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1Certificate(Packet):
    name = "TLSv1 Certificate"
    fields_desc = [ FieldThreeBytesLenField("length", None, length_of="certificate"),
                    StrLenField("certificate", "", length_from=lambda pkt:pkt.length),
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
