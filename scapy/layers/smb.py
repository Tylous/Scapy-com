## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
SMB (Server Message Block), also known as CIFS.
"""

from scapy.packet import *
from scapy.fields import *
from scapy.layers.ms import *
from scapy.layers.netbios import NBTDatagram,NBTSession


### Wishlist ###
# Support additional information levels
# Mailslot protocol, Browser protocol (\MAILSLOT\BROWSE), etc.
# LANMAN API (\PIPE\LANMAN), other pipe protocols?
# Somehow support old dialect versions of current commands?

################################################################################
##                                 CONSTANTS                                  ##
################################################################################

############################## Enumerated Values ###############################

smb_command_codes = {0x00:"CREATE_DIRECTORY",
                     0x01:"DELETE_DIRECTORY",
                     0x02:"OPEN",
                     0x03:"CREATE",
                     0x04:"CLOSE",
                     0x05:"FLUSH",
                     0x06:"DELETE",
                     0x07:"RENAME",
                     0x08:"QUERY_INFORMATION",
                     0x09:"SET_INFORMATION",
                     0x0A:"READ",
                     0x0B:"WRITE",
                     0x0C:"LOCK_BYTE_RANGE",
                     0x0D:"UNLOCK_BYTE_RANGE",
                     0x0E:"CREATE_TEMPORARY",
                     0x0F:"CREATE_NEW",
                     0x10:"CHECK_DIRECTORY",
                     0x11:"PROCESS_EXIT",
                     0x12:"SEEK",
                     0x13:"LOCK_AND_READ",
                     0x14:"WRITE_AND_UNLOCK",
                     #0x15-0x19: unused
                     0x1A:"READ_RAW",
                     0x1B:"READ_MPX",
                     0x1C:"READ_MPX_SECONDARY", # obsolete (LANMAN1.0)
                     0x1D:"WRITE_RAW",
                     0x1E:"WRITE_MPX",
                     0x1F:"WRITE_MPX_SECONDARY", # obsolete (LANMAN1.0)
                     0x20:"WRITE_COMPLETE",
                     0x21:"QUERY_SERVER", # not implemented
                     0x22:"SET_INFORMATION2",
                     0x23:"QUERY_INFORMATION2",
                     0x24:"LOCKING_ANDX",
                     0x25:"TRANSACTION",
                     0x26:"TRANSACTION_SECONDARY",
                     0x27:"IOCTL",
                     0x28:"IOCTL_SECONDARY", # obsolete (LANMAN1.0)
                     0x29:"COPY", # obsolete (LANMAN1.0)
                     0x2A:"MOVE", # obsolete (LANMAN1.0)
                     0x2B:"ECHO",
                     0x2C:"WRITE_AND_CLOSE",
                     0x2D:"OPEN_ANDX",
                     0x2E:"READ_ANDX",
                     0x2F:"WRITE_ANDX",
                     0x30:"NEW_FILE_SIZE", # not implemented
                     0x31:"CLOSE_AND_TREE_DISC", # not implemented (partial in WinNT)
                     0x32:"TRANSACTION2",
                     0x33:"TRANSACTION2_SECONDARY",
                     0x34:"FIND_CLOSE2",
                     0x35:"FIND_NOTIFY_CLOSE", # obsolete (X/Open 2.0)
                     #0x36-0x5F: unused
                     #0x60-0x6F: reserved
                     0x70:"TREE_CONNECT",
                     0x71:"TREE_DISCONNECT",
                     0x72:"NEGOTIATE",
                     0x73:"SESSION_SETUP_ANDX",
                     0x74:"LOGOFF_ANDX",
                     0x75:"TREE_CONNECT_ANDX",
                     #0x76-0x7D: unused
                     0x7E:"SECURITY_PACKAGE_ANDX", # obsolete (LANMAN1.0)
                     #0x7F: unused
                     0x80:"QUERY_INFORMATION_DISK",
                     0x81:"SEARCH",
                     0x82:"FIND",
                     0x83:"FIND_UNIQUE",
                     0x84:"FIND_CLOSE",
                     #0x85-0x9F: unused
                     0xA0:"NT_TRANSACT",
                     0xA1:"NT_TRANSACT_SECONDARY",
                     0xA2:"NT_CREATE_ANDX",
                     #0xA3: unused
                     0xA4:"NT_CANCEL",
                     0xA5:"NT_RENAME",
                     #0xA6-0xBF: unused
                     0xC0:"OPEN_PRINT_FILE",
                     0xC1:"WRITE_PRINT_FILE",
                     0xC2:"CLOSE_PRINT_FILE",
                     0xC3:"GET_PRINT_QUEUE", # obsolete (Core)
                     #0xC4-0xCF: unused
                     #0xD0-0xD7: reserved
                     0xD8:"READ_BULK", # not implemented
                     0xD9:"WRITE_BULK", # not implemented
                     0xDA:"WRITE_BULK_DATA", # not implemented
                     #0xDB-0xFD: unused
                     0xFE:"INVALID", # special value
                     0xFF:"NO_ANDX_COMMAND"} # special value

smb_trans_codes = {0x0001:"SET_NMPIPE_STATE",
                   0x0011:"RAW_READ_NMPIPE",
                   0x0021:"QUERY_NMPIPE_STATE",
                   0x0022:"QUERY_NMPIPE_INFO",
                   0x0023:"PEEK_NMPIPE",
                   0x0026:"TRANSACT_NMPIPE",
                   0x0031:"RAW_WRITE_NMPIPE",
                   0x0036:"READ_NMPIPE",
                   0x0037:"WRITE_NMPIPE",
                   0x0053:"WAIT_NMPIPE",
                   0x0054:"CALL_NMPIPE"}

smb_trans2_codes = {0x0000:"OPEN2",
                    0x0001:"FIND_FIRST2",
                    0x0002:"FIND_NEXT2",
                    0x0003:"QUERY_FS_INFORMATION",
                    0x0004:"SET_FS_INFORMATION",
                    0x0005:"QUERY_PATH_INFORMATION",
                    0x0006:"SET_PATH_INFORMATION",
                    0x0007:"QUERY_FILE_INFORMATION",
                    0x0008:"SET_FILE_INFORMATION",
                    0x0009:"FSCTL", # not implemented
                    0x000A:"IOCTL2", # not implemented
                    0x000B:"FIND_NOTIFY_FIRST", # obsolete (X/Open 2.0)
                    0x000C:"FIND_NOTIFY_NEXT", # obsolete (X/Open 2.0)
                    0x000D:"CREATE_DIRECTORY",
                    0x000E:"SESSION_SETUP", # not implemented
                    0x0010:"GET_DFS_REFERRAL",
                    0x0011:"REPORT_DFS_INCONSISTENCY"} # not implemented

smb_nttrans_codes = {0x0001:"CREATE",
                     0x0002:"IOCTL",
                     0x0003:"SET_SECURITY_DESC",
                     0x0004:"NOTIFY_CHANGE",
                     0x0005:"RENAME", # not implemented
                     0x0006:"QUERY_SECURITY_DESC",
                     0x0007:"QUERY_QUOTA",
                     0x0008:"SET_QUOTA",
                     0x0009:"CREATE2"}

smb_info_find_codes = {0x0001:"FIND_INFO_STANDARD",
                       0x0002:"FIND_INFO_QUERY_EA_SIZE",
                       0x0003:"FIND_INFO_QUERY_EAS_FROM_LIST",
                       0x0101:"FIND_FILE_DIRECTORY_INFO",
                       0x0102:"FIND_FILE_FULL_DIRECTORY_INFO",
                       0x0103:"FIND_FILE_NAMES_INFO",
                       0x0104:"FIND_FILE_BOTH_DIRECTORY_INFO",
                       0x0105:"FIND_FILE_ID_FULL_DIRECTORY_INFO",
                       0x0106:"FIND_FILE_ID_BOTH_DIRECTORY_INFO",
                       0x0202:"FIND_FILE_UNIX_INFO",                # SNIA
                       0x020B:"FIND_FILE_UNIX_INFO2",               # Samba
                       0x0302:"FIND_FILE_BOTH_MAC_HFS_INFO"}        # SNIA
#XXX: wireshark
#    { 0x0202,    "Find File UNIX"},

smb_info_queryfs_codes = {0x0001:"QUERY_FS_INFO_ALLOCATION",
                          0x0002:"QUERY_FS_INFO_VOLUME",
                          0x0102:"QUERY_FS_VOLUME_INFO",
                          0x0103:"QUERY_FS_SIZE_INFO",
                          0x0104:"QUERY_FS_DEVICE_INFO",
                          0x0105:"QUERY_FS_ATTRIBUTE_INFO",
                          0x0200:"QUERY_FS_CIFS_UNIX_INFO",         # SNIA
                          0x0200:"QUERY_FS_POSIX_INFO",             # Samba
                          0x0201:"QUERY_FS_POSIX_WHOAMI",           # Samba
                          0x0301:"QUERY_FS_MAC_FS_INFO",            # SNIA
                            1001:"QUERY_FS_VOLUME_INFORMATION",     # Samba
                            1003:"QUERY_FS_SIZE_INFORMATION",       # Samba
                            1004:"QUERY_FS_DEVICE_INFORMATION",     # Samba
                            1005:"QUERY_FS_ATTRIBUTE_INFORMATION",  # Samba
                            1006:"QUERY_FS_QUOTA_INFORMATION",      # Samba
                            1007:"QUERY_FS_FULL_SIZE_INFORMATION",  # Samba
                            1008:"QUERY_FS_OBJECTID_INFORMATION",   # Samba
                            }
#XXX: wireshark
#    { 0x0101,      "Query FS Label Info"},
#    { 0x0200,      "Unix Query FS Info"},
#    { 0x0301,      "Mac Query FS Info"},
#    { 1001,        "Query FS Label Info"},
#    { 1002,        "Query FS Volume Info"},
#    { 1003,        "Query FS Size Info"},
#    { 1004,        "Query FS Device Info"},
#    { 1005,        "Query FS Attribute Info"},
#    { 1006,        "Query FS Quota Info"},
#    { 1007,        "Query Full FS Size Info"},
#    { 1008,        "Object ID Information"},

smb_info_query_codes = {0x0001:"QUERY_INFO_STANDARD",
                        0x0002:"QUERY_INFO_QUERY_EA_SIZE",
                        0x0003:"QUERY_INFO_QUERY_EAS_FROM_LIST",
                        0x0004:"QUERY_INFO_QUERY_ALL_EAS",
                        0x0006:"QUERY_INFO_IS_NAME_VALID",
                        0x0101:"QUERY_FILE_BASIC_INFO",
                        0x0102:"QUERY_FILE_STANDARD_INFO",
                        0x0103:"QUERY_FILE_EA_INFO",
                        0x0104:"QUERY_FILE_NAME_INFO",
                        0x0107:"QUERY_FILE_ALL_INFO",
                        0x0108:"QUERY_FILE_ALT_NAME_INFO",
                        0x0109:"QUERY_FILE_STREAM_INFO",
                        0x010b:"QUERY_FILE_COMPRESSION_INFO",
                        0x0200:"QUERY_FILE_UNIX_BASIC",                 # SNIA
                        0x0201:"QUERY_FILE_UNIX_LINK",                  # SNIA
                        0x020b:"QUERY_FILE_UNIX_INFO2",                 # Samba
                        0x0306:"QUERY_FILE_MAC_DT_GET_APPL",            # SNIA
                        0x0307:"QUERY_FILE_MAC_DT_GET_ICON",            # SNIA
                        0x0308:"QUERY_FILE_MAC_DT_GET_ICON_INFO",       # SNIA
                          1004:"QUERY_FILE_BASIC_INFORMATION",          # Samba
                          1005:"QUERY_FILE_STANDARD_INFORMATION",       # Samba
                          1006:"QUERY_FILE_INTERNAL_INFORMATION",       # Samba
                          1007:"QUERY_FILE_EA_INFORMATION",             # Samba
                          1008:"QUERY_FILE_ACCESS_INFORMATION",         # Samba
                          1009:"QUERY_FILE_NAME_INFORMATION",           # Samba
                          1014:"QUERY_FILE_POSITION_INFORMATION",       # Samba
                          1016:"QUERY_FILE_MODE_INFORMATION",           # Samba
                          1017:"QUERY_FILE_ALIGNMENT_INFORMATION",      # Samba
                          1018:"QUERY_FILE_ALL_INFORMATION",            # Samba
                          1021:"QUERY_FILE_ALT_NAME_INFORMATION",       # Samba
                          1022:"QUERY_FILE_STREAM_INFORMATION",         # Samba
                          1028:"QUERY_FILE_COMPRESSION_INFORMATION",    # Samba
                          1034:"QUERY_FILE_NETWORK_OPEN_INFORMATION",   # Samba
                          1035:"QUERY_FILE_ATTRIBUTE_TAG_INFORMATION"}  # Samba
#XXX: wireshark
#    { 0x0200,      "Query File Unix Basic"},
#    { 0x0201,      "Query File Unix Link"},
#    { 0x0202,      "Query File Unix Hardlink"},
#    { 0x0204,      "Query File Posix ACL"},
#    { 0x0205,      "Query File Posix XATTR"},
#    { 0x0206,      "Query File Posix Attr Flags"},
#    { 0x0207,      "Query File Posix Permissions"},
#    { 0x0208,      "Query File Posix Lock"},
#    { 1004,        "Query File Basic Info"},
#    { 1005,        "Query File Standard Info"},
#    { 1006,        "Query File Internal Info"},
#    { 1007,        "Query File EA Info"},
# "Level of Interest: Unknown (0x03f0)"
#    { 1009,        "Query File Name Info"},
#    { 1010,        "Query File Rename Info"},
#    { 1011,        "Query File Link Info"},
#    { 1012,        "Query File Names Info"},
#    { 1013,        "Query File Disposition Info"},
#    { 1014,        "Query File Position Info"},
#    { 1015,        "Query File Full EA Info"},
#    { 1016,        "Query File Mode Info"},
#    { 1017,        "Query File Alignment Info"},
#    { 1018,        "Query File All Info"},
#    { 1019,        "Query File Allocation Info"},
#    { 1020,        "Query File End of File Info"},
#    { 1021,        "Query File Alt Name Info"},
#    { 1022,        "Query File Stream Info"},
#    { 1023,        "Query File Pipe Info"},
#    { 1024,        "Query File Pipe Local Info"},
#    { 1025,        "Query File Pipe Remote Info"},
#    { 1026,        "Query File Mailslot Query Info"},
#    { 1027,        "Query File Mailslot Set Info"},
#    { 1028,        "Query File Compression Info"},
#    { 1029,        "Query File ObjectID Info"},
#    { 1030,        "Query File Completion Info"},
#    { 1031,        "Query File Move Cluster Info"},
#    { 1032,        "Query File Quota Info"},
#    { 1033,        "Query File Reparsepoint Info"},
#    { 1034,        "Query File Network Open Info"},
#    { 1035,        "Query File Attribute Tag Info"},
#    { 1036,        "Query File Tracking Info"},
#    { 1037,        "Query File Maximum Info"},

smb_info_set_codes = {0x0001:"SET_INFO_STANDARD",
                      0x0002:"SET_INFO_SET_EAS",
                      0x0101:"SET_FILE_BASIC_INFO",
                      0x0102:"SET_FILE_DISPOSITION_INFO",
                      0x0103:"SET_FILE_ALLOCATION_INFO",
                      0x0104:"SET_FILE_END_OF_FILE_INFO",
                      0x0200:"SET_FILE_UNIX_BASIC",                 # SNIA
                      0x0201:"SET_FILE_UNIX_LINK",                  # SNIA
                      0x0203:"SET_FILE_UNIX_HLINK",                 # SNIA
                      0x0204:"SET_FILE_POSIX_ACL",                  # Samba
                      0x0205:"SET_FILE_XATTR",                      # Samba
                      0x0206:"SET_FILE_ATTR_FLAGS",                 # Samba
                      0x020b:"SET_FILE_UNIX_INFO2",                 # Samba
                      0x0303:"SET_FILE_MAC_SET_FINDER_INFO",        # SNIA
                      0x0304:"SET_FILE_MAC_DT_ADD_APPL",            # SNIA
                      0x0305:"SET_FILE_MAC_DT_REMOVE_APPL",         # SNIA
                      0x0309:"SET_FILE_MAC_DT_ADD_ICON",            # SNIA
                        1004:"SET_FILE_BASIC_INFORMATION",          # Samba
                        1010:"SET_FILE_RENAME_INFORMATION",         # Samba
                        1011:"SET_FILE_LINK_INFORMATION",           # Samba
                        1013:"SET_FILE_DISPOSITION_INFORMATION",    # Samba
                        1014:"SET_FILE_POSITION_INFORMATION",       # Samba
                        1015:"SET_FILE_FULL_EA_INFORMATION",        # Samba
                        1016:"SET_FILE_MODE_INFORMATION",           # Samba
                        1019:"SET_FILE_ALLOCATION_INFORMATION",     # Samba
                        1020:"SET_FILE_END_OF_FILE_INFORMATION",    # Samba
                        1023:"SET_FILE_PIPE_INFORMATION",           # Samba
                        1039:"SET_FILE_VALID_DATA_INFORMATION",     # Samba
                        1040:"SET_FILE_SHORT_NAME_INFORMATION"}     # Samba
#XXX: wireshark
#    { 2,        "Info Query EA Size"},
#    { 4,        "Info Query All EAs"},
#    { 0x0200,    "Set File Unix Basic"},
#    { 0x0201,    "Set File Unix Link"},
#    { 0x0202,    "Set File Unix HardLink"},
#    { 0x0204,    "Set File Unix ACL"},
#    { 0x0205,    "Set File Unix XATTR"},
#    { 0x0206,    "Set File Unix Attr Flags"},
#    { 0x0208,    "Set File Posix Lock"},
#    { 0x0209,    "Set File Posix Open"},
#    { 0x020a,    "Set File Posix Unlink"},
#    { 1004,         "Set File Basic Info"}, (SMB_SET_FILE_BASIC_INFO structure)
#    { 1010,         "Set Rename Information"}, (4+ fields, 54 bytes)
#    { 1013,         "Set Disposition Information"}, (SMB_SET_FILE_DISPOSITION_INFO structure)
#    { 1014,         "Set Position Information"}, (unknown 8 bytes)
#    { 1016,         "Set Mode Information"}, (unknown 4 bytes)
#    { 1019,         "Set Allocation Information"}, (SMB_SET_FILE_ALLOCATION_INFO structure)
#    { 1020,         "Set EOF Information"}, (SMB_SET_FILE_END_OF_FILE_INFO structure)
#    { 1023,         "Set File Pipe Information"},
#    { 1025,         "Set File Pipe Remote Information"},
#    { 1029,         "Set Copy On Write Information"},
#    { 1032,         "Set OLE Class ID Information"},
#    { 1039,         "Set Inherit Context Index Information"},
#    { 1040,         "Set OLE Information (?)"},

smb_error_codes = {0x00000000:"SUCCESS",
                   0x00010001:"ERRDOS/ERRbadfunc",
                   0x00020001:"ERRDOS/ERRbadfile",
                   0x00030001:"ERRDOS/ERRbadpath",
                   0x00040001:"ERRDOS/ERRnofids",
                   0x00050001:"ERRDOS/ERRnoaccess",
                   0x00060001:"ERRDOS/ERRbadfid",
                   0x00070001:"ERRDOS/ERRbadmcb",
                   0x00080001:"ERRDOS/ERRnomem",
                   0x00090001:"ERRDOS/ERRbadmem",
                   0x000a0001:"ERRDOS/ERRbadenv",
                   0x000b0001:"ERRDOS/ERRbadformat",
                   0x000c0001:"ERRDOS/ERRbadaccess",
                   0x000d0001:"ERRDOS/ERRbaddata",
                   0x000f0001:"ERRDOS/ERRbaddrive",
                   0x00100001:"ERRDOS/ERRremcd",
                   0x00110001:"ERRDOS/ERRdiffdevice",
                   0x00120001:"ERRDOS/ERRnofiles",
                   0x00180001:"ERRDOS/ERRbadlength",
                   0x001f0001:"ERRDOS/ERRgeneral",
                   0x00200001:"ERRDOS/ERRbadshare",
                   0x00210001:"ERRDOS/ERRlock",
                   0x00260001:"ERRDOS/ERReof",
                   0x00320001:"ERRDOS/ERRunsup",
                   0x00430001:"ERRDOS/ERRnosuchshare",
                   0x00460001:"ERRDOS/ERRpaused",
                   0x00470001:"ERRDOS/ERRreqnotaccep",
                   0x00500001:"ERRDOS/ERRfilexists",
                   0x00570001:"ERRDOS/ERRinvalidparam",
                   0x00710001:"ERRDOS/ERROR_NO_MORE_SEARCH_HANDLES",
                   0x007C0001:"ERRDOS/ERRunknownlevel",
                   0x00830001:"ERRDOS/ERRinvalidseek",
                   0x009e0001:"ERRDOS/ERROR_NOT_LOCKED",
                   0x00ad0001:"ERRDOS/ERROR_CANCEL_VIOLATION",
                   0x00ae0001:"ERRDOS/ERROR_ATOMIC_LOCKS_NOT_SUPPORTED",
                   0x00e60001:"ERRDOS/ERRbadpipe",
                   0x00e70001:"ERRDOS/ERRpipebusy",
                   0x00e80001:"ERRDOS/ERRpipeclosing",
                   0x00e90001:"ERRDOS/ERRnotconnected",
                   0x00ea0001:"ERRDOS/ERRmoredata",
                   0x00ff0001:"ERRDOS/ERRbadealist",
                   0x010a0001:"ERRDOS/ERROR_CANNOT_COPY",
                   0x01130001:"ERRDOS/ERROR_EAS_DIDNT_FIT",
                   0x011a0001:"ERRDOS/ERROR_EAS_NOT_SUPPORTED",
                   0x02000001:"ERRDOS/ErrQuota",
                   0x02010001:"ERRDOS/ErrNotALink",
                   0x03e20001:"ERRDOS/ERROR_EA_ACCESS_DENIED",
                   0x03fe0001:"ERRDOS/ERR_NOTIFY_ENUM_DIR",
                   0x00010002:"ERRSRV/ERRerror",
                   0x00020002:"ERRSRV/ERRbadpw",
                   0x00030002:"ERRSRV/ERRbadpath",
                   0x00040002:"ERRSRV/ERRaccess",
                   0x00050002:"ERRSRV/ERRinvtid",
                   0x00060002:"ERRSRV/ERRinvnetname",
                   0x00070002:"ERRSRV/ERRinvdevice",
                   0x00100002:"ERRSRV/ERRinvsess",
                   0x00110002:"ERRSRV/ERRworking",
                   0x00120002:"ERRSRV/ERRnotme",
                   0x00160002:"ERRSRV/ERRbadcmd",
                   #0x001f0002:"ERRSRV/ERRgeneral", #XXX: unconfirmed
                   0x00310002:"ERRSRV/ERRqfull",
                   0x00320002:"ERRSRV/ERRqtoobig",
                   0x00330002:"ERRSRV/ERRqeof",
                   0x00340002:"ERRSRV/ERRinvpfid",
                   0x00400002:"ERRSRV/ERRsmbcmd",
                   0x00410002:"ERRSRV/ERRsrverror",
                   0x00420002:"ERRSRV/ERRbadBID",
                   0x00430002:"ERRSRV/ERRfilespecs",
                   0x00440002:"ERRSRV/ERRbadLink",
                   0x00450002:"ERRSRV/ERRbadpermits",
                   0x00460002:"ERRSRV/ERRbadPID",
                   0x00470002:"ERRSRV/ERRsetattrmode",
                   0x00510002:"ERRSRV/ERRpaused",
                   0x00520002:"ERRSRV/ERRmsgoff",
                   0x00530002:"ERRSRV/ERRnoroom",
                   0x00570002:"ERRSRV/ERRrmuns",
                   0x00580002:"ERRSRV/ERRtimeout",
                   0x00590002:"ERRSRV/ERRnoresource",
                   0x005a0002:"ERRSRV/ERRtoomanyuids",
                   0x005b0002:"ERRSRV/ERRbaduid",
                   0x00e90002:"ERRSRV/ERRnotconnected",
                   0x00fa0002:"ERRSRV/ERRusempx",
                   0x00fb0002:"ERRSRV/ERRusestd",
                   0x00fc0002:"ERRSRV/ERRcontmpx",
                   0x00fe0002:"ERRSRV/ERRbadPassword",
                   0x04000002:"ERRSRV/ERR_NOTIFY_ENUM_DIR",
                   0x08bf0002:"ERRSRV/ERRaccountExpired",
                   0x08c00002:"ERRSRV/ERRbadClient",
                   0x08c10002:"ERRSRV/ERRbadLogonTime",
                   0x08c20002:"ERRSRV/ERRpasswordExpired",
                   0xffff0002:"ERRSRV/ERRnosupport",
                   0x00130003:"ERRHRD/ERRnowrite",
                   0x00140003:"ERRHRD/ERRbadunit",
                   0x00150003:"ERRHRD/ERRnotready",
                   0x00160003:"ERRHRD/ERRbadcmd",
                   0x00170003:"ERRHRD/ERRdata",
                   0x00180003:"ERRHRD/ERRbadreq",
                   0x00190003:"ERRHRD/ERRseek",
                   0x001a0003:"ERRHRD/ERRbadmedia",
                   0x001b0003:"ERRHRD/ERRbadsector",
                   0x001c0003:"ERRHRD/ERRnopaper",
                   0x001d0003:"ERRHRD/ERRwrite",
                   0x001e0003:"ERRHRD/ERRread",
                   0x001f0003:"ERRHRD/ERRgeneral",
                   0x00200003:"ERRHRD/ERRbadshare",
                   0x00210003:"ERRHRD/ERRlock",
                   0x00220003:"ERRHRD/ERRwrongdisk",
                   0x00230003:"ERRHRD/ERRFCBUnavail",
                   0x00240003:"ERRHRD/ERRsharebufexc",
                   0x00270003:"ERRHRD/ERRdiskfull",
                   0x000000FF:"ERRCMD",
                   0x0000010c:"STATUS_NOTIFY_ENUM_DIR",
                   0x80000005:"STATUS_BUFFER_OVERFLOW",
                   0x80000006:"STATUS_NO_MORE_FILES",
                   0x8000000e:"STATUS_DEVICE_PAPER_EMPTY",
                   0x80000013:"STATUS_INVALID_EA_NAME",
                   0x80000014:"STATUS_EA_LIST_INCONSISTENT",
                   0x80000015:"STATUS_INVALID_EA_FLAG",
                   0x8000002d:"STATUS_STOPPED_ON_SYMLINK",
                   0xc0000001:"STATUS_UNSUCCESSFUL",
                   0xc0000002:"STATUS_NOT_IMPLEMENTED",
                   0xc0000003:"STATUS_INVALID_INFO_CLASS",
                   0xc0000004:"STATUS_INFO_LENGTH_MISMATCH",
                   0xc0000008:"STATUS_INVALID_HANDLE",
                   0xc000000d:"STATUS_INVALID_PARAMETER",
                   0xc000000e:"STATUS_NO_SUCH_DEVICE",
                   0xc000000f:"STATUS_NO_SUCH_FILE",
                   0xc0000010:"STATUS_INVALID_DEVICE_REQUEST",
                   0xc0000011:"STATUS_END_OF_FILE",
                   0xc0000012:"STATUS_WRONG_VOLUME",
                   0xc0000013:"STATUS_NO_MEDIA_IN_DEVICE",
                   0xc0000015:"STATUS_NONEXISTENT_SECTOR",
                   0xc0000016:"STATUS_MORE_PROCESSING_REQUIRED",
                   0xc0000017:"STATUS_NO_MEMORY",
                   0xc000001e:"STATUS_INVALID_LOCK_SEQUENCE",
                   0xc000001f:"STATUS_INVALID_VIEW_SIZE",
                   0xc0000021:"STATUS_ALREADY_COMMITTED",
                   0xc0000022:"STATUS_ACCESS_DENIED",
                   0xc0000023:"STATUS_BUFFER_TOO_SMALL",
                   0xc0000024:"STATUS_OBJECT_TYPE_MISMATCH",
                   0xc0000032:"STATUS_DISK_CORRUPT_ERROR",
                   0xc0000033:"STATUS_OBJECT_NAME_INVALID",
                   0xc0000034:"STATUS_OBJECT_NAME_NOT_FOUND",
                   0xc0000035:"STATUS_OBJECT_NAME_COLLISION",
                   0xc0000037:"STATUS_PORT_DISCONNECTED",
                   0xc0000039:"STATUS_OBJECT_PATH_INVALID",
                   0xc000003a:"STATUS_OBJECT_PATH_NOT_FOUND",
                   0xc000003b:"STATUS_OBJECT_PATH_SYNTAX_BAD",
                   0xc000003e:"STATUS_DATA_ERROR",
                   0xc000003f:"STATUS_CRC_ERROR",
                   0xc0000040:"STATUS_SECTION_TOO_BIG",
                   0xc0000041:"STATUS_PORT_CONNECTION_REFUSED",
                   0xc0000042:"STATUS_INVALID_PORT_HANDLE",
                   0xc0000043:"STATUS_SHARING_VIOLATION",
                   0xc000004b:"STATUS_THREAD_IS_TERMINATING",
                   0xc000004f:"STATUS_EAS_NOT_SUPPORTED",
                   0xc0000050:"STATUS_EA_TOO_LARGE",
                   0xc0000052:"STATUS_NO_EAS_ON_FILE",
                   0xc0000054:"STATUS_FILE_LOCK_CONFLICT",
                   0xc0000055:"STATUS_LOCK_NOT_GRANTED",
                   0xc0000056:"STATUS_DELETE_PENDING",
                   0xc0000061:"STATUS_PRIVILEGE_NOT_HELD",
                   0xc000006a:"STATUS_WRONG_PASSWORD",
                   0xc000006d:"STATUS_LOGON_FAILURE",
                   0xc000006f:"STATUS_INVALID_LOGON_HOURS",
                   0xc0000070:"STATUS_INVALID_WORKSTATION",
                   0xc0000071:"STATUS_PASSWORD_EXPIRED",
                   0xc0000072:"STATUS_ACCOUNT_DISABLED",
                   0xc0000079:"STATUS_INVALID_SECURITY_DESCR",
                   0xc000007e:"STATUS_RANGE_NOT_LOCKED",
                   0xc000007f:"STATUS_DISK_FULL",
                   0xc0000097:"STATUS_TOO_MANY_PAGING_FILES",
                   0xc000009b:"STATUS_DFS_EXIT_PATH_FOUND",
                   0xc000009c:"STATUS_DATA_ERROR",
                   0xc00000a2:"STATUS_MEDIA_WRITE_PROTECTED",
                   0xc00000a5:"STATUS_BAD_IMPERSONATION_LEVEL",
                   0xc00000ab:"STATUS_INSTANCE_NOT_AVAILABLE",
                   0xc00000ac:"STATUS_PIPE_NOT_AVAILABLE",
                   0xc00000ad:"STATUS_INVALID_PIPE_STATE",
                   0xc00000ae:"STATUS_PIPE_BUSY",
                   0xc00000af:"STATUS_ILLEGAL_FUNCTION",
                   0xc00000b0:"STATUS_PIPE_DISCONNECTED",
                   0xc00000b1:"STATUS_PIPE_CLOSING",
                   0xc00000b4:"STATUS_INVALID_READ_MODE",
                   0xc00000b5:"STATUS_IO_TIMEOUT",
                   0xc00000ba:"STATUS_FILE_IS_A_DIRECTORY",
                   0xc00000bb:"STATUS_NOT_SUPPORTED",
                   0xc00000c4:"STATUS_UNEXPECTED_NETWORK_ERROR",
                   0xc00000c6:"STATUS_PRINT_QUEUE_FULL",
                   0xc00000c7:"STATUS_NO_SPOOL_SPACE",
                   0xc00000c8:"STATUS_PRINT_CANCELLED",
                   0xc00000c9:"STATUS_NETWORK_NAME_DELETED",
                   0xc00000ca:"STATUS_NETWORK_ACCESS_DENIED",
                   0xc00000cb:"STATUS_BAD_DEVICE_TYPE",
                   0xc00000cc:"STATUS_BAD_NETWORK_NAME",
                   0xc00000ce:"STATUS_TOO_MANY_SESSIONS",
                   0xc00000cf:"STATUS_SHARING_PAUSED",
                   0xc00000d0:"STATUS_REQUEST_NOT_ACCEPTED",
                   0xc00000d4:"STATUS_NOT_SAME_DEVICE",
                   0xc00000d5:"STATUS_FILE_RENAMED",
                   0xc00000d9:"STATUS_PIPE_EMPTY",
                   0xc00000fb:"STATUS_REDIRECTOR_NOT_STARTED",
                   0xc0000101:"STATUS_DIRECTORY_NOT_EMPTY",
                   0xc000010a:"STATUS_PROCESS_IS_TERMINATING",
                   0xc000011f:"STATUS_TOO_MANY_OPENED_FILES",
                   0xc0000120:"STATUS_CANCELLED",
                   0xc0000121:"STATUS_CANNOT_DELETE",
                   0xc0000123:"STATUS_FILE_DELETED",
                   0xc0000128:"STATUS_FILE_CLOSED",
                   0xc0000184:"STATUS_INVALID_DEVICE_STATE",
                   0xc0000193:"STATUS_ACCOUNT_EXPIRED",
                   0xc0000203:"STATUS_USER_SESSION_DELETED",
                   0xc0000205:"STATUS_INSUFF_SERVER_RESOURCES",
                   0xc0000224:"STATUS_PASSWORD_MUST_CHANGE",
                   0xc0000235:"STATUS_HANDLE_NOT_CLOSABLE",
                   0xc0000257:"STATUS_PATH_NOT_COVERED",
                   0xc000035c:"STATUS_NETWORK_SESSION_EXPIRED",
                   0xc000205a:"STATUS_SMB_TOO_MANY_UIDS"}

fsctl_codes = {0x00090000:"FSCTL_REQUEST_OPLOCK_LEVEL_1",         #not supported
               0x00090004:"FSCTL_REQUEST_OPLOCK_LEVEL_2",         #not supported
               0x00090008:"FSCTL_REQUEST_BATCH_OPLOCK",           #not supported
               0x0009000c:"FSCTL_OPLOCK_BREAK_ACKNOWLEDGE",       #not supported
               0x00090010:"FSCTL_OPBATCH_ACK_CLOSE_PENDING",      #not supported
               0x00090014:"FSCTL_OPLOCK_BREAK_NOTIFY",            #not supported
               0x0009002c:"FSCTL_IS_PATHNAME_VALID",
               0x0009003b:"FSCTL_QUERY_RETRIEVAL_POINTERS",       #not supported
               0x0009003c:"FSCTL_GET_COMPRESSION",
               0x00090054:"FSCTL_INVALIDATE_VOLUMES",             #not supported
               0x00090058:"FSCTL_QUERY_FAT_BPB",
               0x0009005c:"FSCTL_REQUEST_FILTER_OPLOCK",          #not supported
               0x00090060:"FSCTL_FILESYSTEM_GET_STATISTICS",
               0x00090064:"FSCTL_GET_NTFS_VOLUME_DATA",
               0x00090068:"FSCTL_GET_NTFS_FILE_RECORD",           #not supported
               0x0009006f:"FSCTL_GET_VOLUME_BITMAP",              #not supported
               0x00090073:"FSCTL_GET_RETRIEVAL_POINTERS",
               0x00090074:"FSCTL_MOVE_FILE",                      #not supported
               0x0009008f:"FSCTL_FIND_FILES_BY_SID",
               0x00090098:"FSCTL_SET_OBJECT_ID",
               0x0009009c:"FSCTL_GET_OBJECT_ID",
               0x000900a0:"FSCTL_DELETE_OBJECT_ID",
               0x000900a4:"FSCTL_SET_REPARSE_POINT",
               0x000900a8:"FSCTL_GET_REPARSE_POINT",
               0x000900ac:"FSCTL_DELETE_REPARSE_POINT",
               0x000900b3:"FSCTL_ENUM_USN_DATA",                  #not supported
               0x000900bb:"FSCTL_READ_USN_JOURNAL",               #not supported
               0x000900bc:"FSCTL_SET_OBJECT_ID_EXTENDED",
               0x000900c0:"FSCTL_CREATE_OR_GET_OBJECT_ID",
               0x000900c4:"FSCTL_SET_SPARSE",
               0x000900d7:"FSCTL_SET_ENCRYPTION",
               0x000900e7:"FSCTL_CREATE_USN_JOURNAL",             #not supported
               0x000900eb:"FSCTL_READ_FILE_USN_DATA",
               0x000900ef:"FSCTL_WRITE_USN_CLOSE_RECORD",
               0x000900f4:"FSCTL_QUERY_USN_JOURNAL",              #not supported
               0x000900f8:"FSCTL_DELETE_USN_JOURNAL",             #not supported
               0x000900fc:"FSCTL_MARK_HANDLE",                    #not supported
               0x00090100:"FSCTL_SIS_COPYFILE",
               0x00090117:"FSCTL_RECALL_FILE",
               0x00090138:"FSCTL_QUERY_SPARING_INFO",
               0x0009013c:"FSCTL_QUERY_ON_DISK_VOLUME_INFO",
               0x00090194:"FSCTL_SET_ZERO_ON_DEALLOCATION",
               0x000901f0:"FSCTL_QUERY_DEPENDENT_VOLUME",         #not supported
               0x000901f4:"FSCTL_SD_GLOBAL_CHANGE",               #not supported
               0x000901f8:"FSCTL_TXFS_READ_BACKUP_INFORMATION2",  #not supported
               0x00090200:"FSCTL_TXFS_WRITE_BACKUP_INFORMATION2", #not supported
               0x00090230:"FSCTL_GET_BOOT_AREA_INFO",             #not supported
               0x00090234:"FSCTL_GET_RETRIEVAL_POINTER_BASE",     #not supported
               0x00090238:"FSCTL_SET_PERSISTENT_VOLUME_STATE",    #not supported
               0x0009023c:"FSCTL_QUERY_PERSISTENT_VOLUME_STATE",  #not supported
               0x00090240:"FSCTL_REQUEST_OPLOCK",                 #not supported
               0x000940cf:"FSCTL_QUERY_ALLOCATED_RANGES",
               0x00094148:"FSCTL_TXFS_QUERY_RM_INFORMATION",      #not supported
               0x00094160:"FSCTL_TXFS_READ_BACKUP_INFORMATION",   #not supported
               0x0009416c:"FSCTL_TXFS_GET_METADATA_INFO",         #not supported
               0x00094170:"FSCTL_TXFS_GET_TRANSACTED_VERSION",    #not supported
               0x0009418c:"FSCTL_TXFS_TRANSACTION_ACTIVE",        #not supported
               0x000941e4:"FSCTL_TXFS_LIST_TRANSACTIONS",         #not supported
               0x000980c8:"FSCTL_SET_ZERO_DATA",
               0x00098134:"FSCTL_SET_DEFECT_MANAGEMENT",
               0x00098144:"FSCTL_TXFS_MODIFY_RM",                 #not supported
               0x00098150:"FSCTL_TXFS_ROLLFORWARD_REDO",          #not supported
               0x00098154:"FSCTL_TXFS_ROLLFORWARD_UNDO",          #not supported
               0x00098158:"FSCTL_TXFS_START_RM",                  #not supported
               0x0009815c:"FSCTL_TXFS_SHUTDOWN_RM",               #not supported
               0x00098164:"FSCTL_TXFS_WRITE_BACKUP_INFORMATION",  #not supported
               0x00098168:"FSCTL_TXFS_CREATE_SECONDARY_RM",       #not supported
               0x00098178:"FSCTL_TXFS_SAVEPOINT_INFORMATION",     #not supported
               0x0009817c:"FSCTL_TXFS_CREATE_MINIVERSION",        #not supported
               0x0009c040:"FSCTL_SET_COMPRESSION",
               0x00110000:"FSCTL_PIPE_ASSIGN_EVENT",              #not supported
               0x00110018:"FSCTL_PIPE_WAIT",
               0x0011400c:"FSCTL_PIPE_PEEK",
               0x0011c017:"FSCTL_PIPE_TRANSCEIVE",
               0x00140078:"FSCTL_SRV_REQUEST_RESUME_KEY",
               0x001400ec:"FSCTL_LMR_SET_LINK_TRACKING_INFORMATION",
               0x00144064:"FSCTL_SRV_ENUMERATE_SNAPSHOTS",
               0x001440F2:"FSCTL_SRV_COPYCHUNK"}


smb_enum_NamedPipeType = {0:"byte",1:"message"}

smb_enum_GrantedAccess = {0:"READ",1:"WRITE",2:"READ_WRITE"}

smb_enum_ResourceType = {0:"Disk",1:"ByteModePipe",2:"MessageModePipe",
                         3:"Printer",4:"CommDevice",0xFFFF:"Unknown"}

smb_enum_OpenResult = {1:"opened",2:"created",3:"trunced"}

smb_enum_ResumeKeyLength = {0:"initial search",21:"resume search"}

smb_enum_CreateDisposition = {0:"SUPERSEDE",1:"OPEN",2:"CREATE",
                              3:"OPEN_IF",4:"OVERWRITE",5:"OVERWRITE_IF"}

smb_enum_ImpersonationLevel = {0:"ANONYMOUS",1:"IDENTIFICATION",
                               2:"IMPERSONATION",3:"DELEGATION"}

smb_enum_OpLockLevel = {0:"None",1:"Exclusive",2:"Batch",3:"Level II"}

smb_enum_DeviceType = {0x0001:"BEEP",
                       0x0002:"CD_ROM",
                       0x0003:"CD_ROM_FILE_SYSTEM",
                       0x0004:"CONTROLLER",
                       0x0005:"DATALINK",
                       0x0006:"DFS",
                       0x0007:"DISK",
                       0x0008:"DISK_FILE_SYSTEM",
                       0x0009:"FILE_SYSTEM",
                       0x000a:"INPORT_PORT",
                       0x000b:"KEYBOARD",
                       0x000c:"MAILSLOT",
                       0x000d:"MIDI_IN",
                       0x000e:"MIDI_OUT",
                       0x000f:"MOUSE",
                       0x0010:"MULTI_UNC_PROVIDER",
                       0x0011:"NAMED_PIPE",
                       0x0012:"NETWORK",
                       0x0013:"NETWORK_BROWSER",
                       0x0014:"NETWORK_FILE_SYSTEM",
                       0x0015:"NULL",
                       0x0016:"PARALLEL_PORT",
                       0x0017:"PHYSICAL_NETCARD",
                       0x0018:"PRINTER",
                       0x0019:"SCANNER",
                       0x001a:"SERIAL_MOUSE_PORT",
                       0x001b:"SERIAL_PORT",
                       0x001c:"SCREEN",
                       0x001d:"SOUND",
                       0x001e:"STREAMS",
                       0x001f:"TAPE",
                       0x0020:"TAPE_FILE_SYSTEM",
                       0x0021:"TRANSPORT",
                       0x0022:"UNKNOWN",
                       0x0023:"VIDEO",
                       0x0024:"VIRTUAL_DISK",
                       0x0025:"WAVE_IN",
                       0x0026:"WAVE_OUT",
                       0x0027:"8042_PORT",
                       0x0028:"NETWORK_REDIRECTOR",
                       0x0029:"BATTERY",
                       0x002a:"BUS_EXTENDER",
                       0x002b:"MODEM",
                       0x002c:"VDM"}


################################# Flag Values ##################################

SMB_FILE_ATTRIBUTES = ["READONLY","HIDDEN","SYSTEM","VOLUME",
                       "DIRECTORY","ARCHIVE"]

SMB_FILE_ATTRIBUTES_SEARCH = SMB_FILE_ATTRIBUTES+["","",
                              "SEARCH_READONLY","SEARCH_HIDDEN","SEARCH_SYSTEM","",
                              "SEARCH_DIRECTORY","SEARCH_ARCHIVE"]

SMB_EXT_FILE_ATTR = SMB_FILE_ATTRIBUTES+["","NORMAL",
                     "TEMPORARY","SPARSE","REPARSE_POINT","COMPRESSED",
                     "OFFLINE","NOT_CONTENT_INDEXED","ENCRYPTED","",
                     "","","","",
                     "","","","",
                     "POSIX_SEMANTICS","BACKUP_SEMANTICS","DELETE_ON_CLOSE","SEQUENTIAL_SCAN",
                     "RANDOM_ACCESS","NO_BUFFERING","","WRITE_THROUGH"]

smb_flags_TRANSACTION_Flags = ["DISCONNECT_TID","NO_RESPONSE","EXTENDED_SIGNATURES","EXTENDED_RESPONSE"]

smb_flags_header_Flags = ["LOCK_AND_READ_OK","BUF_AVAIL","","CASE_INSENSITIVE",
                          "CANONICALIZED_PATHS","OPLOCK","OPBATCH","REPLY"]

smb_flags_header_Flags2 = ["LONG_NAMES","EAS","SMB_SECURITY_SIGNATURE","COMPRESSED",
                           "SMB_SECURITY_SIGNATURE_REQUIRED","","IS_LONG_NAME","",
                           "","","REPARSE_PATH","EXTENDED_SECURITY",
                           "DFS","PAGING_IO","NT_STATUS","UNICODE"]

smb_flags_WriteMode = ["WritethroughMode","ReadBytesAvailable","NamedPipeRaw","NamedPipeStart",
                       "","","","ConnectionlessMode"]

smb_flags_TypeOfLock =["SHARED_LOCK","OPLOCK_RELEASE","CHANGE_LOCKTYPE","CANCEL_LOCK",
                       "LARGE_FILES"]

smb_flags_COPY_Flags = ["DEST_FILE","DEST_DIRECTORY","COPY_DEST_MODE","COPY_SOURCE_MODE",
                        "VERIFY_ALL","TREE"]

smb_flags_OPEN_ANDX_Flags = ["QUERY_INFORMATION","OPLOCK","OPBATCH","EXTENDED_RESPONSE"]

smb_flags_SecurityMode = ["user level","encrypt passwords"]

smb_flags_BlockMode = ["Read Block Raw","Write Block Raw"]

smb_flags_SecurityMode_NT = ["USER_SECURITY","ENCRYPT_PASSWORDS",
                             "SECURITY_SIGNATURES_ENABLED","SECURITY_SIGNATURES_REQUIRED"]

smb_flags_Capabilities = ["RAW_MODE","MPX_MODE","UNICODE","LARGE_FILES",
                          "NT_SMBS","RPC_REMOTE_APIS","STATUS32","LEVEL_II_OPLOCKS",
                          "LOCK_AND_READ","NT_FIND","BULK_TRANSFER","COMPRESSED",
                          "DFS","INFOLEVEL_PASSTHRU","LARGE_READX","LARGE_WRITEX",
                          "LWIO","","","",
                          "","","","UNIX",
                          "","COMPRESSED_DATA","","",
                          "","DYNAMIC_REAUTH","PERSISTENT_HANDLES","EXTENDED_SECURITY"]

smb_flags_Action = ["GUEST","USE_LANMAN_KEY"]

smb_flags_OptionalSupport = ["SUPPORT_SEARCH_BITS","SHARE_IS_IN_DFS"]

smb_flags_NT_CREATE_Flags = ["","REQUEST_OPLOCK","REQUEST_OPBATCH","OPEN_TARGET_DIR",
                             "REQUEST_EXTENDED_RESPONSE"]

smb_flags_ShareAccess = ["SHARE_READ","SHARE_WRITE","SHARE_DELETE"]

smb_flags_CreateOptions = ["DIRECTORY_FILE","WRITE_THROUGH","SEQUENTIAL_ONLY","NO_INTERMEDIATE_BUFFERING",
                           "SYNCHRONOUS_IO_ALERT","SYNCHRONOUS_IO_NONALERT","NON_DIRECTORY_FILE","CREATE_TREE_CONNECTION",
                           "COMPLETE_IF_OPLOCKED","NO_EA_KNOWLEDGE","OPEN_FOR_RECOVERY","RANDOM_ACCESS",
                           "DELETE_ON_CLOSE","OPEN_BY_FILE_ID","OPEN_FOR_BACKUP_INTENT","NO_COMPRESSION",
                           "","","","",
                           "RESERVE_OPFILTER","","OPEN_NO_RECALL","OPEN_FOR_FREE_SPACE_QUERY"]

smb_flags_SecurityFlags = ["CONTEXT_TRACKING","EFFECTIVE_ONLY"]

smb_flags_FileStatusFlags = ["NO_EAS","NO_SUBSTREAMS","NO_REPARSETAG"]

smb_flags_PipeState = ["","","","",
                       "","","","",
                       "ReadMode","","","",
                       "","","","Blocking"]

smb_flags_TRANS2_OPEN2_Flags = ["REQ_ATTRIB","REQ_OPLOCK","REQ_OPBATCH","REQ_EASIZE"]

smb_flags_TRANS2_FIND_Flags = ["CLOSE_AFTER_REQUEST","CLOSE_AT_EOS","RETURN_RESUME_KEYS","CONTINUE_FROM_LAST",
                               "WITH_BACKUP_INTENT"]

smb_flags_SecurityInformation = ["OWNER","GROUP","DACL","SACL"]

smb_flags_CompletionFilter = ["FILE_NAME","DIR_NAME","ATTRIBUTES","SIZE",
                              "LAST_WRITE","LAST_ACCESS","CREATION","EA",
                              "SECURITY","STREAM_NAME","STREAM_SIZE","STREAM_WRITE"]

smb_flags_DeviceCharacteristics = ["REMOVABLE_MEDIA","READ_ONLY_DEVICE","FLOPPY_DISKETTE","WRITE_ONCE_MEDIA",
                                   "REMOTE_DEVICE","DEVICE_IS_MOUNTED","VIRTUAL_VOLUME"]

smb_flags_FileSystemAttributes = ["CASE_SENSITIVE_SEARCH","CASE_PRESERVED_NAMES","UNICODE_ON_DISK","PERSISTENT_ACLS",
                                  "FILE_COMPRESSION","VOLUME_QUOTAS","SUPPORTS_SPARSE_FILES","SUPPORTS_REPARSE_POINTS",
                                  "SUPPORTS_REMOTE_STORAGE","","","",
                                  "","","","VOLUME_IS_COMPRESSED",
                                  "SUPPORTS_OBJECT_IDS","SUPPORTS_ENCRYPTION","NAMED_STREAMS","READ_ONLY_VOLUME",
                                  "SEQUENTIAL_WRITE_ONCE","SUPPORTS_TRANSACTIONS","SUPPORTS_HARD_LINKS","SUPPORTS_EXTENDED_ATTRIBUTES",
                                  "SUPPORTS_OPEN_BY_FILE_ID","SUPPORTS_USN_JOURNAL"]


################################################################################
##                              SPECIAL CLASSES                               ##
################################################################################

#################################### Fields ####################################

class SMB_UCHAR_LenField(UCHAR_LenField):
    def i2m(self, pkt, x):
        self.codec = "utf-16-le" if (pkt and pkt.is_unicode()) else "ascii"
        return StrField.i2m(self, pkt, x)
    def m2i(self, pkt, x):
        self.codec = "utf-16-le" if (pkt and pkt.is_unicode()) else "ascii"
        return StrField.m2i(self, pkt, x)

class SMB_STRING_Field(StrNullField,SMB_UCHAR_LenField):
    def __init__(self, name, default, fmt="H", remain=0):
        StrNullField.__init__(self, name, default, fmt, remain)
    def i2m(self, pkt, x):
        return SMB_UCHAR_LenField.i2m(self, pkt, x)
    def m2i(self, pkt, x):
        return SMB_UCHAR_LenField.m2i(self, pkt, x)

class OEM_STRING_Field(StrNullField):
    def __init__(self, name, default, fmt="H", remain=0):
        StrNullField.__init__(self, name, default, fmt, remain, codec=None)

class SMB_DATE_Field(LEShortField):
    re_ymd = re.compile("^([0-9]+)[-/]([0-9]+)[-/]([0-9]+)$")
    def __init__(self, name, default):
        if default is None:
            default = "1980/01/01"
        LEShortField.__init__(self, name, default)
    def h2i(self, pkt, val):
        if isinstance(val, VolatileValue):
            return val
        try:
            if type(val) is str:
                y,m,d = [int(x) for x in self.re_ymd.match(val).groups()]
                y -= 1980
                if y < 0:
                    raise
                return (d & 0x001F) + (m<<5 & 0x01E0) + (y<<9 & 0xFE00)
            else:
                val = int(val)
        except:
            raise Scapy_Exception("Failed to parse date - use 'YYYY/MM/DD' format (years 1980-2107)")
        
        return val
    def i2h(self, pkt, val):
        if isinstance(val, VolatileValue):
            return val
        d = val & 0x001F
        m = (val & 0x01E0) >> 5
        y = ((val & 0xFE00) >> 9) + 1980
        return "%04d/%02d/%02d" % (y,m,d)
    def i2repr(self, pkt, x):
        return "%s (0x%04x)" % (self.i2h(pkt,x), x)

class SMB_TIME_Field(LEShortField):
    re_hms = re.compile("^([0-9]+):([0-9]+):([0-9]+)$")
    def __init__(self, name, default):
        if default is None:
            default = "00:00:00"
        LEShortField.__init__(self, name, default)
    def h2i(self, pkt, val):
        if isinstance(val, VolatileValue):
            return val
        try:
            if type(val) is str:
                h,m,s = [int(x) for x in self.re_hms.match(val).groups()]
                return (s/2 & 0x001F) + (m<<5 & 0x07E0) + (h<<11 & 0xF800)
            else:
                val = int(val)
        except:
            raise Scapy_Exception("Failed to parse time - use 'HH:MM:SS' format")

        return val
    def i2h(self, pkt, val):
        if isinstance(val, VolatileValue):
            return val
        s = (val & 0x001F) * 2
        m = (val & 0x07E0) >> 5
        h = (val & 0xF800) >> 11
        return "%02d:%02d:%02d" % (h,m,s)
    def i2repr(self, pkt, x):
        return "%s (0x%04x)" % (self.i2h(pkt,x), x)

class SMB_GEA_Field(StrField):
    def __init__(self, name, default):
        StrField.__init__(self, name, default)
    def i2len(self, pkt, i):
        return len(self.i2m(pkt, i))+2
    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        return s+chr(len(val))+val+"\x00"
    def getfield(self, pkt, s):
        l = ord(s[0])
        s = s[1:]
        return s[l+1:], self.m2i(pkt,s[:l])
    def randval(self):
        return RandBin(RandNum(0,255))

class SMBDialectField(OEM_STRING_Field):
    def i2len(self, pkt, i):
        return OEM_STRING_Field.i2len(self, pkt, i)+1
    def addfield(self, pkt, s, val):
        return OEM_STRING_Field.addfield(self, pkt, s, "\x02"+val)
    def getfield(self, pkt, s):
        return OEM_STRING_Field.getfield(self, pkt, s[1:])

class SMBUnicodePadField(StrLenField):
    """
    Padding field for SMB messages.
    `padtype` should be set to 1 or 2 for Pad1 or Pad2 fields in transactions.
    `padlen` should be the number of padding bytes (0 or 1) required to align
        any following Unicode field(s), or a function that returns this number.
    """
    def __init__(self, name, default, padtype=0, padlen=None):
        self.padlen = padlen
        if type(padlen) is int:
            length_from = lambda pkt:padlen
        else:
            length_from = padlen
        StrLenField.__init__(self, name, default, length_from=length_from)
        self.padtype = padtype
    def getpadlen(self, pkt, x):
        l = 0
        if self.padtype == 1 and pkt.ParameterOffset > 0:
            c = pkt.calc_trans_fields(1)
            l = pkt.ParameterOffset-c
        elif self.padtype == 2 and pkt.DataOffset > 0:
            c = pkt.calc_trans_fields(2)
            l = pkt.DataOffset-c
        elif pkt.is_unicode() and self.length_from is not None:
            l = self.length_from(pkt) % 2
        if l <= 0:
            l = 0
        return l
    def i2len(self, pkt, x):
        if x is None:
            return self.getpadlen(pkt, x)
        else:
            return StrLenField.i2len(self, pkt, x)
    def i2m(self, pkt, x):
        if x is None:
            l = self.getpadlen(pkt, x)
            x = "\x00"*l
        else:
            x = StrLenField.i2m(self, pkt, x)
        return x
    def getfield(self, pkt, s):
        l = self.getpadlen(pkt, s)
        return s[l:], self.m2i(pkt,s[:l])
    def randval(self):
        return self.default


################################ Data Structures ###############################

class SMB_Directory_Information(Packet):
    name = "SMB Directory Information"
    fields_desc = [ByteField("ResumeKey_Reserved",0),
                   StrFixedLenField("ResumeKey_ServerState","",16),
                   StrFixedLenField("ResumeKey_ClientState","",4),
                   LEFlagsField("FileAttributes",0,8,SMB_FILE_ATTRIBUTES),
                   SMB_TIME_Field("LastWriteTime",None),
                   SMB_DATE_Field("LastWriteDate",None),
                   LEIntField("FileSize",0),
                   StrFixedLenField("FileName","",13)]

class SMB_LOCKING_ANDX_RANGE32(Packet):
    name = "SMB Locking Byte Range (32-bit)"
    fields_desc = [LEShortField("PID",0),
                   LEIntField("ByteOffset",0),
                   LEIntField("LengthInBytes",0)]

class SMB_LOCKING_ANDX_RANGE64(Packet):
    name = "SMB Locking Byte Range (64-bit)"
    fields_desc = [LEShortField("PID",0),
                   LEShortField("Pad",0),
                   LEIntField("ByteOffsetHigh",0),
                   LEIntField("ByteOffsetLow",0),
                   LEIntField("LengthInBytesHigh",0),
                   LEIntField("LengthInBytesLow",0)]

class SMB_FILE_NOTIFY_INFORMATION(Packet):
    name = "SMB File Notify Information"
    fields_desc = [FieldLenField("NextEntryOffset",None,length_of="FileName1",fmt="<I",
                                 adjust=lambda pkt,x:x+12),
                   LEIntEnumField("Action",0,{1:"ADDED",2:"REMOVED",
                                              3:"MODIFIED",4:"RENAMED_OLD_NAME",
                                              5:"RENAMED_NEW_NAME",6:"ADDED_STREAM",
                                              7:"REMOVED_STREAM",8:"MODIFIED_STREAM"}),
                   FieldLenField("FileNameLength",None,length_of="FileName1",fmt="<I"),
                   StrLenField("FileName1","",codec="utf-16-le", #XXX: check unicode flag?
                               length_from=lambda pkt:pkt.FileNameLength)]

class SMB_FEA(Packet):
    name = "SMB Full Extended Attribute (FEA)"
    fields_desc = [FlagsField("Flags",0,8,FEA_flags),
                   FieldLenField("AttributeNameLengthInBytes",None,length_of="AttributeName",fmt="B"),
                   FieldLenField("AttributeValueLengthInBytes",None,length_of="AttributeValue",fmt="<H"),
                   StrLenField("AttributeName","",
                               length_from=lambda pkt:pkt.AttributeNameLengthInBytes),
                   StrFixedLenField("Padding","",1),
                   StrLenField("AttributeValue","",
                               length_from=lambda pkt:pkt.AttributeValueLengthInBytes)]


############################ Common Field Sequences ############################

class _smb_fields_SMB_NMPIPE_STATUS(Packet):
    fields_desc = [BitField("NMPipeStatus_ICount",0,8),
                   BitField("NMPipeStatus_Blocking",0,1),
                   BitEnumField("NMPipeStatus_Endpoint",0,1,{0:"client",1:"server"}),
                   BitField("NMPipeStatus_Reserved",0,2),
                   BitEnumField("NMPipeStatus_NamedPipeType",0,2,smb_enum_NamedPipeType),
                   BitEnumField("NMPipeStatus_ReadMode",0,2,smb_enum_NamedPipeType)]

class _smb_fields_SMB_FEA_LIST(Packet):
    fields_desc = [FieldLenField("SizeOfListInBytes",None,length_of="FEAList",fmt="<I",
                                 adjust=lambda pkt,x:x+4),
                   PacketListField("FEAList",[],SMB_FEA,
                                   length_from=lambda pkt:pkt.SizeOfListInBytes-4)]

class _smb_fields_SMB_GEA_LIST(Packet):
    fields_desc = [ConditionalField(FieldLenField("SizeOfListInBytes",None,length_of="GEAList",fmt="<I",
                                                  adjust=lambda pkt,x:x+4),
                                    lambda pkt:pkt.InformationLevel == 0x0003),
                   ConditionalField(FieldListField("GEAList",[],SMB_GEA_Field("GEA",""),
                                                    length_from=lambda pkt:pkt.SizeOfListInBytes-4),
                                    lambda pkt:pkt.InformationLevel == 0x0003)]

class _smb_fields_AccessMode(Packet):
    fields_desc = [BitField("AccessMode_Reserved2",0,1),
                   BitEnumField("AccessMode_SharingMode",0,3,{0:"compat",1:"deny rwx",2:"deny w",
                                                              3:"deny rx",4:"deny none"}),
                   BitField("AccessMode_Reserved1",0,1),
                   BitEnumField("AccessMode_AccessMode",0,3,{0:"r",1:"w",2:"rw",3:"x"}),
                   BitField("AccessMode_Reserved5",0,1),
                   BitField("AccessMode_WritethroughMode",0,1),
                   BitField("AccessMode_Reserved4",0,1),
                   BitField("AccessMode_CacheMode",0,1),
                   BitField("AccessMode_Reserved3",0,1),
                   BitEnumField("AccessMode_ReferenceLocality",0,3,{0:"unk",1:"seq",
                                                                    2:"rand",3:"randlocal"})]

class _smb_fields_OpenMode(Packet):
    fields_desc = [BitField("OpenMode_Reserved1",0,3),
                   BitEnumField("OpenMode_CreateFile",0,1,{0:"fail",1:"create"}),
                   BitField("OpenMode_Reserved2",0,2),
                   BitEnumField("OpenMode_FileExistsOpts",0,2,{0:"fail",1:"append",2:"trunc"}),
                   BitField("OpenMode_Reserved3",0,8)]

class _smb_fields_OpenResults(Packet):
    fields_desc = [BitField("OpenResults_Reserved1",0,6),
                   BitEnumField("OpenResults_CreateFile",0,2,smb_enum_OpenResult),
                   BitField("OpenResults_LockStatus",0,1),
                   BitField("OpenResults_Reserved2",0,7)]

class _smb_fields_AndX(Packet):
    fields_desc = [XByteEnumField("AndXCommand",0xFF,smb_command_codes),
                   ByteField("AndXReserved",0),
                   LEShortField("AndXOffset",None)]

class _smb_fields_TRANS_Req_count_offset(Packet):
    fields_desc = [LEShortField("TotalParameterCount",None),
                   LEShortField("TotalDataCount",None),
                   LEShortField("MaxParameterCount",0),
                   LEShortField("MaxDataCount",0),
                   ByteField("MaxSetupCount",0),
                   ByteField("Reserved1",0),
                   LEFlagsField("Flags",0,16,smb_flags_TRANSACTION_Flags),
                   LEIntField("Timeout",0),
                   LEShortField("Reserved2",0),
                   LEShortField("ParameterCount",None),
                   LEShortField("ParameterOffset",None),
                   LEShortField("DataCount",None),
                   LEShortField("DataOffset",None)]

class _smb_fields_TRANS_Res_count_offset(Packet):
    fields_desc = [LEShortField("TotalParameterCount",None),
                   LEShortField("TotalDataCount",None),
                   LEShortField("Reserved1",0),
                   LEShortField("ParameterCount",None),
                   LEShortField("ParameterOffset",None),
                   LEShortField("ParameterDisplacement",0),
                   LEShortField("DataCount",None),
                   LEShortField("DataOffset",None),
                   LEShortField("DataDisplacement",0)]

class _smb_fields_TRANS_SECONDARY_count_offset(Packet):
    fields_desc = [LEShortField("TotalParameterCount",None),
                   LEShortField("TotalDataCount",None),
                   LEShortField("ParameterCount",None),
                   LEShortField("ParameterOffset",None),
                   LEShortField("ParameterDisplacement",0),
                   LEShortField("DataCount",None),
                   LEShortField("DataOffset",None),
                   LEShortField("DataDisplacement",0)]

class _smb_fields_TRANS_Req_HDR_with_fid(Packet):
    fields_desc = [ByteField("WordCount",16),
                   _smb_fields_TRANS_Req_count_offset,
                   ByteField("SetupCount",2),
                   ByteField("Reserved3",0),
                   XLEShortEnumField("Subcommand",0xFFFF,smb_trans_codes),
                   LEShortField("FID",0),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("Name","\\PIPE\\")]

class _smb_fields_TRANS_Req_HDR_with_priority(Packet):
    fields_desc = [ByteField("WordCount",16),
                   _smb_fields_TRANS_Req_count_offset,
                   ByteField("SetupCount",2),
                   ByteField("Reserved3",0),
                   XLEShortEnumField("Subcommand",0xFFFF,smb_trans_codes),
                   LEShortField("Priority",0),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("Name","\\PIPE\\")]

class _smb_fields_TRANS_Res_HDR(Packet):
    fields_desc = [ByteField("WordCount",10),
                   _smb_fields_TRANS_Res_count_offset,
                   ByteField("SetupCount",0),
                   ByteField("Reserved2",0),
                   LEShortField("ByteCount",None)]

class _smb_fields_TRANS2_Req_HDR(Packet):
    fields_desc = [ByteField("WordCount",15),
                   _smb_fields_TRANS_Req_count_offset,
                   ByteField("SetupCount",1),
                   ByteField("Reserved3",0),
                   XLEShortEnumField("Setup",0xFFFF,smb_trans2_codes),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("Name",""),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0)]

class _smb_fields_NT_TRANSACT_Req_count_offset(Packet):
    fields_desc = [ByteField("MaxSetupCount",0),
                   LEShortField("Reserved1",0),
                   LEIntField("TotalParameterCount",None),
                   LEIntField("TotalDataCount",None),
                   LEIntField("MaxParameterCount",0),
                   LEIntField("MaxDataCount",0),
                   LEIntField("ParameterCount",None),
                   LEIntField("ParameterOffset",None),
                   LEIntField("DataCount",None),
                   LEIntField("DataOffset",None)]

class _smb_fields_NT_TRANSACT_Res_count_offset(Packet):
    fields_desc = [LEBitField("Reserved1",0,8*3),
                   LEIntField("TotalParameterCount",None),
                   LEIntField("TotalDataCount",None),
                   LEIntField("ParameterCount",None),
                   LEIntField("ParameterOffset",None),
                   LEIntField("ParameterDisplacement",0),
                   LEIntField("DataCount",None),
                   LEIntField("DataOffset",None),
                   LEIntField("DataDisplacement",0)]

class _smb_fields_NT_TRANSACT_Req_HDR_setup0(Packet):
    fields_desc = [ByteField("WordCount",19),
                   _smb_fields_NT_TRANSACT_Req_count_offset,
                   ByteField("SetupCount",0),
                   XLEShortEnumField("Function",0xFFFF,smb_nttrans_codes),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1)]

class _smb_fields_NT_TRANSACT_Req_HDR_setup4(Packet):
    fields_desc = [ByteField("WordCount",23),
                   _smb_fields_NT_TRANSACT_Req_count_offset,
                   ByteField("SetupCount",4),
                   XLEShortEnumField("Function",0xFFFF,smb_nttrans_codes)]

class _smb_fields_NT_TRANSACT_Res_HDR(Packet):
    fields_desc = [ByteField("WordCount",18),
                   _smb_fields_NT_TRANSACT_Res_count_offset,
                   ByteField("SetupCount",0),
                   LEShortField("ByteCount",None)]

class _smb_fields_date_time(Packet):
    fields_desc = [SMB_DATE_Field("CreationDate",None),
                   SMB_TIME_Field("CreationTime",None),
                   SMB_DATE_Field("LastAccessDate",None),
                   SMB_TIME_Field("LastAccessTime",None),
                   SMB_DATE_Field("LastWriteDate",None),
                   SMB_TIME_Field("LastWriteTime",None)]

class _smb_fields_FILE_BASIC_INFO(Packet):
    fields_desc = [FILETIME_Field("CreationTime",None),
                   FILETIME_Field("LastAccessTime",None),
                   FILETIME_Field("LastWriteTime",None),
                   FILETIME_Field("ChangeTime",None),
                   LEFlagsField("ExtFileAttributes",0,32,SMB_EXT_FILE_ATTR)]

class _smb_fields_FILE_DIRECTORY_INFO(Packet):
    fields_desc = [LEIntField("NextEntryOffset",None),
                   LEIntField("FileIndex",0),
                   FILETIME_Field("CreationTime",None),
                   FILETIME_Field("LastAccessTime",None),
                   FILETIME_Field("LastWriteTime",None),
                   FILETIME_Field("ChangeTime",None),
                   LESignedLongField("EndOfFile",0),
                   LESignedLongField("AllocationSize",0),
                   LEFlagsField("ExtFileAttributes",0,32,SMB_EXT_FILE_ATTR),
                   FieldLenField("FileNameLength",None,length_of="FileName",fmt="<I")]


################################ Guess Payload #################################

class _SMBGuessPayload:
    def guess_payload_class(self, payload):
        r = "_Req"
        e = ""
        h = None
        if "ANDX" in self.name:
            cnum = self.AndXCommand
            ul = self.underlayer
            while ul:
                if isinstance(ul, SMB_Header):
                    if ul.Flags & 0x80:
                        r = "_Res"
                    if ul.Flags2 & 0x0800:
                        e = "_ExtSec"
                    h = ul.hashret()
                    break
                else:
                    ul = ul.underlayer
            else:
                if "Response" in self.name:
                    r = "_Res"
                if "Extended Security" in self.name:
                    e = "_ExtSec"
        else:
            cnum = self.Command
            if self.Flags & 0x80:
                r = "_Res"
            if self.Flags2 & 0x0800:
                e = "_ExtSec"
            h = self.hashret()
        
        default = SMB_COM
        com = cls = ""
        if cnum in smb_command_codes:
            com = smb_command_codes[cnum]
            cls = "SMB_COM_%s%s" % (com,r)
        
        if com in ["INVALID","NO_ANDX_COMMAND"]:
            return Raw
        elif com == "SESSION_SETUP_ANDX":
            cls = cls+e
        elif r == "_Req":
            if com == "TRANSACTION" and len(payload) >= 31:
                if ord(payload[27]) == 2:
                    code = struct.unpack("<H",payload[29:31])[0]
                    if code in smb_trans_codes:
                        default = SMB_COM_TRANSACTION_Req
                        cls = "SMB_TRANS_%s_Req" % smb_trans_codes[code]
                elif ord(payload[27]) == 3 and struct.unpack("<H",payload[29:31])[0] == 0x0001:
                    cls = "SMB_TRANS_MAILSLOT_WRITE_Req" #TODO: check for "\MAILSLOT\" or "\PIPE\"
            elif com == "TRANSACTION2" and len(payload) >= 31:
                if ord(payload[27]) == 1:
                    code = struct.unpack("<H",payload[29:31])[0]
                    if code in smb_trans2_codes:
                        default = SMB_COM_TRANSACTION2_Req
                        cls = "SMB_TRANS2_%s_Req" % smb_trans2_codes[code]
            elif com == "NT_TRANSACT" and len(payload) >= 39:
                code = struct.unpack("<H",payload[37:39])[0]
                if code in smb_nttrans_codes:
                    default = SMB_COM_NT_TRANSACT_Req
                    cls = "SMB_NT_TRANSACT_%s_Req" % smb_nttrans_codes[code]
        elif r == "_Res":
            if len(payload) >= 2 and payload[:2] == "\x00"*2:
                if com in ["TRANSACTION","TRANSACTION2","NT_TRANSACT","IOCTL"]:
                    cls = "SMB_COM_%s_ResI" % com
                else:
                    default = SMB_COM_Null
            elif h in SMB_TRANS.smb_trans_db:
                t = SMB_TRANS.smb_trans_db[h]
                if t['com'] == cnum:
                    if com == "TRANSACTION":
                        default = SMB_COM_TRANSACTION_Res
                        if t['sc'] == 2 and t['sub'] in smb_trans_codes:
                            cls = "SMB_TRANS_%s_Res" % smb_trans_codes[t['sub']]
                        elif t['sc'] == 3 and t['sub'] == 0x0001:
                            cls = "SMB_TRANS_MAILSLOT_WRITE_Res" #TODO: confirm this
                    elif (com == "TRANSACTION2" and t['sc'] == 1 and
                          t['sub'] in smb_trans2_codes):
                        default = SMB_COM_TRANSACTION2_Res
                        cls = "SMB_TRANS2_%s_Res" % smb_trans2_codes[t['sub']]
                    elif com == "NT_TRANSACT" and t['sub'] in smb_nttrans_codes:
                        default = SMB_COM_NT_TRANSACT_Res
                        cls = "SMB_NT_TRANSACT_%s_Res" % smb_nttrans_codes[t['sub']]
            elif com == "TRANSACTION2" and len(payload) >= 31:
                if struct.unpack("<H",payload[29:31])[0] == 0x0010:
                    cls = "SMB_TRANS2_GET_DFS_REFERRAL_Res"
            elif com == "NEGOTIATE":
                if ord(payload[0]) == 13:
                    cls = "SMB_COM_NEGOTIATE_ResLANMAN21"
                    #cls = "SMB_COM_NEGOTIATE_ResLANMAN" #XXX: not detected
                elif ord(payload[0]) == 17:
                    cls = "SMB_COM_NEGOTIATE_ResNTLM012"+e
            elif com == "OPEN_ANDX" and ord(payload[0]) > 15:
                cls = "SMB_COM_OPEN_ANDX_ResExtend"
            elif com == "TREE_CONNECT_ANDX" and ord(payload[0]) > 3:
                cls = "SMB_COM_TREE_CONNECT_ANDX_ResExtend"
            elif com == "NT_CREATE_ANDX" and ord(payload[0]) > 34:
                cls = "SMB_COM_NT_CREATE_ANDX_ResExtend"
        
        return globals().get(cls, default)


class _SMBGuessPayload_INFO:
    def guess_info_class(self, payload, codes):
        cls = Raw
        d = self.get_trans_db()
        if d and d["info"] in codes:
            s = "SMB_%s" % codes[d["info"]]
            if "SMB_FIND_INFO" in s and d["resume"]:
                s += "_Resume"
            cls = globals().get(s, Raw)
        return cls

class _SMBGuessPayload_INFO_FIND(_SMBGuessPayload_INFO):
    def guess_payload_class(self, payload):
        return self.guess_info_class(payload, smb_info_find_codes)

class _SMBGuessPayload_INFO_QUERYFS(_SMBGuessPayload_INFO):
    def guess_payload_class(self, payload):
        return self.guess_info_class(payload, smb_info_queryfs_codes)

class _SMBGuessPayload_INFO_QUERY(_SMBGuessPayload_INFO):
    def guess_payload_class(self, payload):
        return self.guess_info_class(payload, smb_info_query_codes)


################################################################################
##                                SMB PACKETS                                 ##
################################################################################

################################ Common Packets ################################

class SMB_Header(_SMBGuessPayload,Packet):
    name="SMB Header"
    fields_desc = [StrFixedLenField("Protocol","\xffSMB",4),
                   XByteEnumField("Command",0xFE,smb_command_codes),
                   XLEIntEnumField("Status",0,smb_error_codes),
                   LEFlagsField("Flags",0,8,smb_flags_header_Flags),
                   LEFlagsField("Flags2",0,16,smb_flags_header_Flags2),
                   LEShortField("PIDHigh",0),
                   StrFixedLenField("SecurityFeatures","",8),
                   LEShortField("Reserved",0),
                   LEShortField("TID",0),
                   LEShortField("PIDLow",0),
                   LEShortField("UID",0),
                   LEShortField("MID",0)]
    def hashret(self):
        return struct.pack("HHH",self.PIDHigh,self.PIDLow,self.MID)
    def answers(self, other):
        if (isinstance(other, SMB_Header) and
            self.PIDHigh == other.PIDHigh and
            self.PIDLow == other.PIDLow and
            self.MID == other.MID and
            self.Flags & 0x80 and
            not other.Flags & 0x80):
            return 1
        return 0


class SMB_COM(Packet):
    name="SMB Command"
    fields_desc = [FieldLenField("WordCount",None,length_of="Words",fmt="B",
                                 adjust=lambda pkt,x:x/2),
                   StrLenField("Words","",
                               length_from=lambda pkt:pkt.WordCount*2),
                   FieldLenField("ByteCount",None,length_of="Bytes",fmt="<H"),
                   StrLenField("Bytes","",
                               length_from=lambda pkt:pkt.ByteCount)]
    def is_unicode(self):
        if not isinstance(self.underlayer, SMB_Header):
            return None
        return bool(self.underlayer.Flags2 & 0x8000)

class SMB_COM_Null(SMB_COM):
    name="SMB Command (no data)"
    fields_desc = [ByteField("WordCount",0),
                   LEShortField("ByteCount",0)]


class SMB_ANDX(_SMBGuessPayload,SMB_COM):
    name="SMB ANDX Command"
    fields_desc = [ByteField("WordCount",2),
                   _smb_fields_AndX,
                   LEShortField("ByteCount",0)]
    def post_build(self, p, pay):
        if self.AndXOffset is None and self.AndXCommand != 0xFF:
            off = 32+len(p)
            ul = self
            while isinstance(ul.underlayer, SMB_ANDX):
                ul = ul.underlayer.copy()
                del(ul.payload)
                off += len(ul)
            p = p[:3]+struct.pack("<H",off)+p[5:]
        p += pay
        return p


class SMB_TRANS(SMB_COM):
    name="SMB Transact Command"
    smb_trans_db = {} #TODO: make a nice class for this, like conf.neighbor?
    def calc_trans_fields(self, pad=None):
        """
        Returns the offsets and lengths of the parameter and data portions
            of the packet, or the offset of the given pad field (1 or 2).
        """
        fn = [f.name for f in self.fields_desc]
        
        setup_len = 0
        if "SetupCount" in fn:
            start = fn.index("SetupCount")+1
            if "Reserved" in fn[start] or fn[start] == "Function":
                start += 1
            for n in fn[start:fn.index("ByteCount")]:
                setup_len += self.getfieldlen(n)
        
        fn = fn[fn.index("ByteCount"):]
        offset = self.base_len-2+setup_len
        length = 0
        
        off_b = offset
        off_p = off_d = len_p = len_d = 0
        part = 0.0
        while fn:
            n = fn.pop(0)
            if (pad,n) in [(1,"Pad1"), (2,"Pad2")]: # specified pad reached
                return 32+offset
            fl = self.getfieldlen(n)
            if type(fl) is float: # for bit fields
                part += fl
                if part == int(part): # next byte reached
                    fl = int(part)
                    part = 0.0
                else:
                    continue
            if n == "Pad1": # Parameters are present
                off_p = 32+offset+fl
                length = 0
            elif n == "Pad2": # Data is present
                off_d = 32+offset+fl
                if off_p:
                    len_p = length
                length = 0
            else:
                length += fl
            offset += fl
        if off_d:
            len_d = length + len(self.payload)
        elif off_p:
            len_p = length + len(self.payload)
        if not len_d:
            off_d = 0
        if not len_p:
            off_p = 0
        
        return off_b,off_p,off_d,len_p,len_d
    def post_build_trans(self, p, pay, off_po, off_do, off_tpc, off_pc, off_tdc, off_dc, longfld=False):
        """
        Calculates and sets the parameter and data-related fields, given their
            offsets.  For 32-bit fields (NT Trans), set longfld to True.
        """
        if longfld:
            sz,fmt = 4,"<I"
        else:
            sz,fmt = 2,"<H"
        p += pay
        off_b,off_p,off_d,len_p,len_d = self.calc_trans_fields()
        if self.ByteCount is None:
            l = len(p)-off_b-2
            p = p[:off_b]+struct.pack("<H",l)+p[off_b+2:]
        if self.ParameterOffset is None:
            p = p[:off_po]+struct.pack(fmt,off_p)+p[off_po+sz:]
        if self.DataOffset is None:
            p = p[:off_do]+struct.pack(fmt,off_d)+p[off_do+sz:]
        if self.TotalParameterCount is None:
            p = p[:off_tpc]+struct.pack(fmt,len_p)+p[off_tpc+sz:]
        if self.ParameterCount is None:
            p = p[:off_pc]+struct.pack(fmt,len_p)+p[off_pc+sz:]
        if self.TotalDataCount is None:
            p = p[:off_tdc]+struct.pack(fmt,len_d)+p[off_tdc+sz:]
        if self.DataCount is None:
            p = p[:off_dc]+struct.pack(fmt,len_d)+p[off_dc+sz:]
        return p
    def add_trans_db(self, com, sc, sub, info=None, resume=None, replace=True):
        """
        Associates a PID/MID set with a transaction subcommand.
        """
        if not isinstance(self.underlayer, SMB_Header):
            return False
        h = self.underlayer.hashret()
        if h == "\x00"*6 or (h in SMB_TRANS.smb_trans_db and not replace):
            return False
        SMB_TRANS.smb_trans_db[h] = {"com":com,"sc":sc,"sub":sub,"info":info,"resume":resume}
        return True
    def get_trans_db(self):
        """
        Returns the transaction subcommand associated with this packet.
        This is necessary to determine the type of transaction replies.
        """
        if not isinstance(self.underlayer, SMB_Header):
            return None
        h = self.underlayer.hashret()
        if h not in SMB_TRANS.smb_trans_db:
            return None
        return SMB_TRANS.smb_trans_db[h]


################################# SMB Commands #################################

class SMB_COM_CREATE_DIRECTORY_Req(SMB_COM):
    name="SMB Command - CREATE_DIRECTORY - Request"
    overload_fields = {SMB_Header:{"Command":0x00,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",0),
                   FieldLenField("ByteCount",None,length_of="DirectoryName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("DirectoryName","")]

class SMB_COM_CREATE_DIRECTORY_Res(SMB_COM_Null):
    name="SMB Command - CREATE_DIRECTORY - Response"
    overload_fields = {SMB_Header:{"Command":0x00,"Flags":0x80}}


class SMB_COM_DELETE_DIRECTORY_Req(SMB_COM_CREATE_DIRECTORY_Req):
    name="SMB Command - DELETE_DIRECTORY - Request"
    overload_fields = {SMB_Header:{"Command":0x01,"Flags":0x00}}

class SMB_COM_DELETE_DIRECTORY_Res(SMB_COM_Null):
    name="SMB Command - DELETE_DIRECTORY - Response"
    overload_fields = {SMB_Header:{"Command":0x01,"Flags":0x80}}


class SMB_COM_OPEN_Req(SMB_COM):
    name="SMB Command - OPEN - Request"
    overload_fields = {SMB_Header:{"Command":0x02,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",2),
                   _smb_fields_AccessMode,
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_OPEN_Res(SMB_COM):
    name="SMB Command - OPEN - Response"
    overload_fields = {SMB_Header:{"Command":0x02,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",7),
                   LEShortField("FID",0),
                   LEFlagsField("FileAttrs",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("LastModified",0),
                   LEIntField("FileSize",0),
                   _smb_fields_AccessMode,
                   LEShortField("ByteCount",0)]


class SMB_COM_CREATE_Req(SMB_COM):
    name="SMB Command - CREATE - Request"
    overload_fields = {SMB_Header:{"Command":0x03,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",3),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("CreationTime",0),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_CREATE_Res(SMB_COM):
    name="SMB Command - CREATE - Response"
    overload_fields = {SMB_Header:{"Command":0x03,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("FID",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_CLOSE_Req(SMB_COM):
    name="SMB Command - CLOSE - Request"
    overload_fields = {SMB_Header:{"Command":0x04,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",3),
                   LEShortField("FID",0),
                   LETimeField("LastTimeModified",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_CLOSE_Res(SMB_COM_Null):
    name="SMB Command - CLOSE - Response"
    overload_fields = {SMB_Header:{"Command":0x04,"Flags":0x80}}


class SMB_COM_FLUSH_Req(SMB_COM_CREATE_Res):
    name="SMB Command - FLUSH - Request"
    overload_fields = {SMB_Header:{"Command":0x05,"Flags":0x00}}

class SMB_COM_FLUSH_Res(SMB_COM_Null):
    name="SMB Command - FLUSH - Response"
    overload_fields = {SMB_Header:{"Command":0x05,"Flags":0x80}}


class SMB_COM_DELETE_Req(SMB_COM):
    name="SMB Command - DELETE - Request"
    overload_fields = {SMB_Header:{"Command":0x06,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",1),
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_DELETE_Res(SMB_COM_Null):
    name="SMB Command - DELETE - Response"
    overload_fields = {SMB_Header:{"Command":0x06,"Flags":0x80}}


class SMB_COM_RENAME_Req(SMB_COM):
    name="SMB Command - RENAME - Request"
    overload_fields = {SMB_Header:{"Command":0x07,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",1),
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LEShortField("ByteCount",None),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("OldFileName",""),
                   ByteField("BufferFormat2",4),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("NewFileName","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-5
            p = p[:3]+struct.pack("<H",l)+p[5:]
        p += pay
        return p

class SMB_COM_RENAME_Res(SMB_COM_Null):
    name="SMB Command - RENAME - Response"
    overload_fields = {SMB_Header:{"Command":0x07,"Flags":0x80}}


class SMB_COM_QUERY_INFORMATION_Req(SMB_COM):
    name="SMB Command - QUERY_INFORMATION - Request"
    overload_fields = {SMB_Header:{"Command":0x08,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",0),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_QUERY_INFORMATION_Res(SMB_COM):
    name="SMB Command - QUERY_INFORMATION - Response"
    overload_fields = {SMB_Header:{"Command":0x08,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",10),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("LastWriteTime",0),
                   LEIntField("FileSize",0),
                   LEBitField("Reserved",0,16*5),
                   LEShortField("ByteCount",0)]


class SMB_COM_SET_INFORMATION_Req(SMB_COM):
    name="SMB Command - SET_INFORMATION - Request"
    overload_fields = {SMB_Header:{"Command":0x09,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",8),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("LastWriteTime",0),
                   LEBitField("Reserved",0,16*5),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_SET_INFORMATION_Res(SMB_COM_Null):
    name="SMB Command - SET_INFORMATION - Response"
    overload_fields = {SMB_Header:{"Command":0x09,"Flags":0x80}}


class SMB_COM_READ_Req(SMB_COM):
    name="SMB Command - READ - Request"
    overload_fields = {SMB_Header:{"Command":0x0A,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",5),
                   LEShortField("FID",0),
                   LEShortField("CountOfBytesToRead",0),
                   LEIntField("ReadOffsetInBytes",0),
                   LEShortField("EstimateOfRemainingBytesToBeRead",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_READ_Res(SMB_COM):
    name="SMB Command - READ - Response"
    overload_fields = {SMB_Header:{"Command":0x0A,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",5),
                   FieldLenField("CountOfBytesReturned",None,length_of="Bytes",fmt="<H"),
                   LEBitField("Reserved",0,16*4),
                   FieldLenField("ByteCount",None,length_of="Bytes",fmt="<H",
                                 adjust=lambda pkt,x:x+3),
                   ByteField("BufferFormat",1),
                   FieldLenField("CountOfBytesRead",None,length_of="Bytes",fmt="<H"),
                   StrLenField("Bytes","",
                               length_from=lambda pkt:pkt.CountOfBytesRead)]


class SMB_COM_WRITE_Req(SMB_COM):
    name="SMB Command - WRITE - Request"
    overload_fields = {SMB_Header:{"Command":0x0B,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",5),
                   LEShortField("FID",0),
                   FieldLenField("CountOfBytesToWrite",None,length_of="Data",fmt="<H"),
                   LEIntField("WriteOffsetInBytes",0),
                   LEShortField("EstimateOfRemainingBytesToBeWritten",0),
                   FieldLenField("ByteCount",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:x+3),
                   ByteField("BufferFormat",1),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]

class SMB_COM_WRITE_Res(SMB_COM):
    name="SMB Command - WRITE - Response"
    overload_fields = {SMB_Header:{"Command":0x0B,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("CountOfBytesWritten",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_LOCK_BYTE_RANGE_Req(SMB_COM):
    name="SMB Command - LOCK_BYTE_RANGE - Request"
    overload_fields = {SMB_Header:{"Command":0x0C,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",5),
                   LEShortField("FID",0),
                   LEIntField("CountOfBytesToLock",0),
                   LEIntField("LockOffsetInBytes",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_LOCK_BYTE_RANGE_Res(SMB_COM_Null):
    name="SMB Command - LOCK_BYTE_RANGE - Response"
    overload_fields = {SMB_Header:{"Command":0x0C,"Flags":0x80}}


class SMB_COM_UNLOCK_BYTE_RANGE_Req(SMB_COM):
    name="SMB Command - UNLOCK_BYTE_RANGE - Request"
    overload_fields = {SMB_Header:{"Command":0x0D,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",5),
                   LEShortField("FID",0),
                   LEIntField("CountOfBytesToUnlock",0),
                   LEIntField("UnlockOffsetInBytes",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_UNLOCK_BYTE_RANGE_Res(SMB_COM_Null):
    name="SMB Command - UNLOCK_BYTE_RANGE - Response"
    overload_fields = {SMB_Header:{"Command":0x0D,"Flags":0x80}}


class SMB_COM_CREATE_TEMPORARY_Req(SMB_COM):
    name="SMB Command - CREATE_TEMPORARY - Request"
    overload_fields = {SMB_Header:{"Command":0x0E,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",3),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("CreationTime",0),
                   FieldLenField("ByteCount",None,length_of="DirectoryName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("DirectoryName","")]

class SMB_COM_CREATE_TEMPORARY_Res(SMB_COM):
    name="SMB Command - CREATE_TEMPORARY - Response"
    overload_fields = {SMB_Header:{"Command":0x0E,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("FID",0),
                   FieldLenField("ByteCount",None,length_of="TemporaryFileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("TemporaryFileName","")]


class SMB_COM_CREATE_NEW_Req(SMB_COM_CREATE_Req):
    name="SMB Command - CREATE_NEW - Request"
    overload_fields = {SMB_Header:{"Command":0x0F,"Flags":0x00}}

class SMB_COM_CREATE_NEW_Res(SMB_COM_CREATE_Res):
    name="SMB Command - CREATE_NEW - Response"
    overload_fields = {SMB_Header:{"Command":0x0F,"Flags":0x80}}


class SMB_COM_CHECK_DIRECTORY_Req(SMB_COM_CREATE_DIRECTORY_Req):
    name="SMB Command - CHECK_DIRECTORY - Request"
    overload_fields = {SMB_Header:{"Command":0x10,"Flags":0x00}}

class SMB_COM_CHECK_DIRECTORY_Res(SMB_COM_Null):
    name="SMB Command - CHECK_DIRECTORY - Response"
    overload_fields = {SMB_Header:{"Command":0x10,"Flags":0x80}}


class SMB_COM_PROCESS_EXIT_Req(SMB_COM_Null):
    name="SMB Command - PROCESS_EXIT - Request"
    overload_fields = {SMB_Header:{"Command":0x11,"Flags":0x00}}

class SMB_COM_PROCESS_EXIT_Res(SMB_COM_Null):
    name="SMB Command - PROCESS_EXIT - Response"
    overload_fields = {SMB_Header:{"Command":0x11,"Flags":0x80}}


class SMB_COM_SEEK_Req(SMB_COM):
    name="SMB Command - SEEK - Request"
    overload_fields = {SMB_Header:{"Command":0x12,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",4),
                   LEShortField("FID",0),
                   LEShortEnumField("Mode",0,{0:"start",1:"current",2:"end"}),
                   LEIntField("Offset",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_SEEK_Res(SMB_COM):
    name="SMB Command - SEEK - Response"
    overload_fields = {SMB_Header:{"Command":0x12,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",2),
                   LEIntField("Offset",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_LOCK_AND_READ_Req(SMB_COM_READ_Req):
    name="SMB Command - LOCK_AND_READ - Request"
    overload_fields = {SMB_Header:{"Command":0x13,"Flags":0x00}}

class SMB_COM_LOCK_AND_READ_Res(SMB_COM_READ_Res):
    name="SMB Command - LOCK_AND_READ - Response"
    overload_fields = {SMB_Header:{"Command":0x13,"Flags":0x80}}


class SMB_COM_WRITE_AND_UNLOCK_Req(SMB_COM_WRITE_Req):
    name="SMB Command - WRITE_AND_UNLOCK - Request"
    overload_fields = {SMB_Header:{"Command":0x14,"Flags":0x00}}

class SMB_COM_WRITE_AND_UNLOCK_Res(SMB_COM_WRITE_Res):
    name="SMB Command - WRITE_AND_UNLOCK - Response"
    overload_fields = {SMB_Header:{"Command":0x14,"Flags":0x80}}


class SMB_COM_READ_RAW_Req(SMB_COM):
    name="SMB Command - READ_RAW - Request"
    overload_fields = {SMB_Header:{"Command":0x1A,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",8),
                   LEShortField("FID",0),
                   LEIntField("Offset",0),
                   LEShortField("MaxCountOfBytesToReturn",0),
                   LEShortField("MinCountOfBytesToReturn",0),
                   LEIntField("Timeout",0),
                   LEShortField("Reserved",0),
                   ConditionalField(LEIntField("OffsetHigh",0),
                                    lambda pkt:pkt.WordCount >= 10),
                   LEShortField("ByteCount",0)]


class SMB_COM_READ_MPX_Req(SMB_COM):
    name="SMB Command - READ_MPX - Request"
    overload_fields = {SMB_Header:{"Command":0x1B,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",8),
                   LEShortField("FID",0),
                   LEIntField("Offset",0),
                   LEShortField("MaxCountOfBytesToReturn",0),
                   LEShortField("MinCountOfBytesToReturn",0),
                   LEIntField("Timeout",0),
                   LEShortField("Reserved",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_READ_MPX_Res(SMB_COM):
    name="SMB Command - READ_MPX - Response"
    overload_fields = {SMB_Header:{"Command":0x1B,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",8),
                   LEIntField("Offset",0),
                   LEShortField("Count",0),
                   LEShortField("Remaining",0),
                   LEShortField("DataCompactionMode",0),
                   LEShortField("Reserved",0),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   LEShortField("DataOffset",None),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]
    def post_build(self, p, pay):
        if self.DataOffset is None:
            if self.getfieldlen("Data") > 0:
                offset = 32+19+self.getfieldlen("Padding")
            else:
                offset = 0
            p = p[:15]+struct.pack("<H",offset)+p[17:]
        if self.ByteCount is None:
            l = len(p)-19
            p = p[:17]+struct.pack("<H",l)+p[19:]
        p += pay
        return p


class SMB_COM_READ_MPX_SECONDARY_Res(SMB_COM_READ_MPX_Res): # obsolete (LANMAN1.0)
    name="SMB Command - READ_MPX_SECONDARY - Response"
    overload_fields = {SMB_Header:{"Command":0x1C,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",8),
                   LEIntField("Offset",0),
                   LEShortField("Count",0),
                   LEShortField("Remaining",0),
                   LEIntField("Reserved",0),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   LEShortField("DataOffset",None),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]


class SMB_COM_WRITE_RAW_Req(SMB_COM):
    name="SMB Command - WRITE_RAW - Request"
    overload_fields = {SMB_Header:{"Command":0x1D,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",12),
                   LEShortField("FID",0),
                   FieldLenField("CountOfBytes",None,length_of="Data",fmt="<H"),
                   LEShortField("Reserved1",0),
                   LEIntField("Offset",0),
                   LEIntField("Timeout",0),
                   LEFlagsField("WriteMode",0,16,smb_flags_WriteMode),
                   LEIntField("Reserved2",0),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   LEShortField("DataOffset",None),
                   ConditionalField(LEIntField("OffsetHigh",0),
                                    lambda pkt:pkt.WordCount >= 14),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]
    def post_build(self, p, pay):
        if self.DataOffset is None:
            if self.getfieldlen("Data") > 0:
                offset = 32+27+self.getfieldlen("Padding")
                if self.WordCount >= 14:
                    offset += 4
            else:
                offset = 0
            p = p[:23]+struct.pack("<H",offset)+p[25:]
        if self.ByteCount is None:
            offset = 27
            if self.WordCount >= 14:
                offset += 4
            l = len(p)-offset
            p = p[:offset-2]+struct.pack("<H",l)+p[offset:]
        p += pay
        return p

class SMB_COM_WRITE_RAW_Res(SMB_COM):
    name="SMB Command - WRITE_RAW - Response"
    overload_fields = {SMB_Header:{"Command":0x1D,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("Available",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_WRITE_MPX_Req(SMB_COM):
    name="SMB Command - WRITE_MPX - Request"
    overload_fields = {SMB_Header:{"Command":0x1E,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",12),
                   LEShortField("FID",0),
                   FieldLenField("TotalByteCount",None,length_of="Data",fmt="<H"),
                   LEShortField("Reserved",0),
                   LEIntField("ByteOffsetToBeginWrite",0),
                   LEIntField("Timeout",0),
                   LEFlagsField("WriteMode",0x0080,16,smb_flags_WriteMode),
                   XLEIntField("RequestMask",0),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   LEShortField("DataOffset",None),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]
    def post_build(self, p, pay):
        if self.DataOffset is None:
            if self.getfieldlen("Data") > 0:
                offset = 32+27+self.getfieldlen("Padding")
            else:
                offset = 0
            p = p[:23]+struct.pack("<H",offset)+p[25:]
        if self.ByteCount is None:
            l = len(p)-27
            p = p[:25]+struct.pack("<H",l)+p[27:]
        p += pay
        return p

class SMB_COM_WRITE_MPX_Res(SMB_COM):
    name="SMB Command - WRITE_MPX - Response"
    overload_fields = {SMB_Header:{"Command":0x1E,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",2),
                   XLEIntField("ResponseMask",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_WRITE_MPX_SECONDARY_Req(SMB_COM_READ_MPX_Res): # obsolete (LANMAN1.0)
    name="SMB Command - WRITE_MPX_SECONDARY - Request"
    overload_fields = {SMB_Header:{"Command":0x1F,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",8),
                   LEShortField("FID",0),
                   FieldLenField("TotalByteCount",None,length_of="Data",fmt="<H"),
                   LEIntField("ByteOffsetToBeginWrite",0),
                   LEIntField("Reserved",0),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   LEShortField("DataOffset",None),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]


class SMB_COM_WRITE_COMPLETE_Res(SMB_COM):
    name="SMB Command - WRITE_COMPLETE - Response"
    overload_fields = {SMB_Header:{"Command":0x20,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("Count",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_SET_INFORMATION2_Req(SMB_COM):
    name="SMB Command - SET_INFORMATION2 - Request"
    overload_fields = {SMB_Header:{"Command":0x22,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",7),
                   LEShortField("FID",0),
                   _smb_fields_date_time,
                   LEShortField("ByteCount",0)]

class SMB_COM_SET_INFORMATION2_Res(SMB_COM_Null):
    name="SMB Command - SET_INFORMATION2 - Response"
    overload_fields = {SMB_Header:{"Command":0x22,"Flags":0x80}}


class SMB_COM_QUERY_INFORMATION2_Req(SMB_COM_CREATE_Res):
    name="SMB Command - QUERY_INFORMATION2 - Request"
    overload_fields = {SMB_Header:{"Command":0x23,"Flags":0x00}}

class SMB_COM_QUERY_INFORMATION2_Res(SMB_COM):
    name="SMB Command - QUERY_INFORMATION2 - Response"
    overload_fields = {SMB_Header:{"Command":0x23,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",11),
                   _smb_fields_date_time,
                   LEIntField("FileDataSize",0),
                   LEIntField("FileAllocationSize",0),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LEShortField("ByteCount",0)]


class SMB_COM_LOCKING_ANDX_Req(SMB_ANDX):
    name="SMB Command - LOCKING_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x24,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",8),
                   _smb_fields_AndX,
                   LEShortField("FID",0),
                   LEFlagsField("TypeOfLock",0,8,smb_flags_TypeOfLock),
                   ByteEnumField("NewOpLockLevel",0,{0:"None",1:"Level II OpLock"}),
                   LEIntEnumField("Timeout",0,{0xFFFFFFFF:"forever"}),
                   FieldLenField("NumberOfRequestedUnlocks",None,count_of="Unlocks32",fmt="<H",
                                 adjust=lambda pkt,x:(pkt.getfieldcount("Unlocks64") if
                                                      pkt.TypeOfLock & 0x10 else x)),
                   FieldLenField("NumberOfRequestedLocks",None,count_of="Locks32",fmt="<H",
                                 adjust=lambda pkt,x:(pkt.getfieldcount("Locks64") if
                                                      pkt.TypeOfLock & 0x10 else x)),
                   LEShortField("ByteCount",None),
                   ConditionalField(PacketListField("Unlocks32",[],SMB_LOCKING_ANDX_RANGE32,
                                                    count_from=lambda pkt:pkt.NumberOfRequestedUnlocks),
                                    lambda pkt:not pkt.TypeOfLock & 0x10),
                   ConditionalField(PacketListField("Locks32",[],SMB_LOCKING_ANDX_RANGE32,
                                                    count_from=lambda pkt:pkt.NumberOfRequestedLocks),
                                    lambda pkt:not pkt.TypeOfLock & 0x10),
                   ConditionalField(PacketListField("Unlocks64",[],SMB_LOCKING_ANDX_RANGE64,
                                                    count_from=lambda pkt:pkt.NumberOfRequestedUnlocks),
                                    lambda pkt:pkt.TypeOfLock & 0x10),
                   ConditionalField(PacketListField("Locks64",[],SMB_LOCKING_ANDX_RANGE64,
                                                    count_from=lambda pkt:pkt.NumberOfRequestedLocks),
                                    lambda pkt:pkt.TypeOfLock & 0x10)]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-19
            p = p[:17]+struct.pack("<H",l)+p[19:]
        return SMB_ANDX.post_build(self, p, pay)

class SMB_COM_LOCKING_ANDX_Res(SMB_ANDX):
    name="SMB Command - LOCKING_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x24,"Flags":0x80}}


class SMB_COM_TRANSACTION_Req(SMB_TRANS):
    name="SMB Command - TRANSACTION - Request"
    base_len = 31
    overload_fields = {SMB_Header:{"Command":0x25,"Flags":0x00}}
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+14),
                   _smb_fields_TRANS_Req_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   ByteField("Reserved3",0),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-14)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("Name",""),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0),
                   StrLenField("Trans_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+pkt.getfieldlen("Trans_Parameters"))%2),
                   StrLenField("Trans_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,21,25,1,19,3,23)
    def post_dissect(self, s):
        sub = None
        if hasattr(self, "Subcommand"):
            sub = self.Subcommand
        elif hasattr(self, "MailSlotOpcode"):
            sub = self.MailSlotOpcode
        elif hasattr(self, "Setup") and type(self.Setup) is list and self.SetupCount > 0:
            sub = self.Setup[0]
        if sub is not None:
            self.add_trans_db(0x25, self.SetupCount, sub)
        return s

class SMB_COM_TRANSACTION_Res(SMB_TRANS):
    name="SMB Command - TRANSACTION - Response"
    base_len = 23
    overload_fields = {SMB_Header:{"Command":0x25,"Flags":0x80}}
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+10),
                   _smb_fields_TRANS_Res_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   ByteField("Reserved2",0),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-10)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Trans_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1+pkt.getfieldlen("Trans_Parameters"))%2),
                   StrLenField("Trans_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        if hasattr(self, "_trans_code"):
            self.add_trans_db(0x25, self._trans_code[0], self._trans_code[1])
        return self.post_build_trans(p,pay,9,15,1,7,3,13)

class SMB_COM_TRANSACTION_ResI(SMB_COM_Null):
    name="SMB Command - TRANSACTION - Interim Response"
    overload_fields = {SMB_Header:{"Command":0x25,"Flags":0x80}}


class SMB_COM_TRANSACTION_SECONDARY_Req(SMB_TRANS):
    name="SMB Command - TRANSACTION_SECONDARY - Request"
    base_len = 19
    overload_fields = {SMB_Header:{"Command":0x26,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",8),
                   _smb_fields_TRANS_SECONDARY_count_offset,
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Trans_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1+pkt.getfieldlen("Trans_Parameters"))%2),
                   StrLenField("Trans_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,7,13,1,5,3,11)


class SMB_COM_IOCTL_Req(SMB_TRANS):
    name="SMB Command - IOCTL - Request"
    base_len = 31
    overload_fields = {SMB_Header:{"Command":0x27,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",14),
                   LEShortField("FID",0),
                   LEShortField("Category",0),
                   LEShortField("Function",0),
                   LEShortField("TotalParameterCount",None),
                   LEShortField("TotalDataCount",None),
                   LEShortField("MaxParameterCount",0),
                   LEShortField("MaxDataCount",0),
                   LEIntField("Timeout",0),
                   LEShortField("Reserved",0),
                   LEShortField("ParameterCount",None),
                   LEShortField("ParameterOffset",None),
                   LEShortField("DataCount",None),
                   LEShortField("DataOffset",None),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1+pkt.getfieldlen("Parameters"))%2),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,23,27,7,21,9,25)

class SMB_COM_IOCTL_Res(SMB_TRANS):
    name="SMB Command - IOCTL - Response"
    base_len = 19
    overload_fields = {SMB_Header:{"Command":0x27,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",8),
                   _smb_fields_TRANS_SECONDARY_count_offset,
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1+pkt.getfieldlen("Parameters"))%2),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,7,13,1,5,3,11)

class SMB_COM_IOCTL_ResI(SMB_COM_Null): # obsolete (LANMAN1.0)
    name="SMB Command - IOCTL - Interim Response"
    overload_fields = {SMB_Header:{"Command":0x27,"Flags":0x80}}


class SMB_COM_IOCTL_SECONDARY_Req(SMB_COM_IOCTL_Res): # obsolete (LANMAN1.0)
    name="SMB Command - IOCTL_SECONDARY - Request"
    overload_fields = {SMB_Header:{"Command":0x28,"Flags":0x00}}


class SMB_COM_COPY_Req(SMB_COM): # obsolete (LANMAN1.0)
    name="SMB Command - COPY - Request"
    overload_fields = {SMB_Header:{"Command":0x29,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",3),
                   LEShortField("TID2",0),
                   _smb_fields_OpenMode,
                   LEFlagsField("Flags",0,16,smb_flags_COPY_Flags),
                   LEShortField("ByteCount",None),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("SourceFileName",""),
                   ByteField("BufferFormat2",4),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("DestFileName","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-9
            p = p[:7]+struct.pack("<H",l)+p[9:]
        p += pay
        return p

class SMB_COM_COPY_Res(SMB_COM): # obsolete (LANMAN1.0)
    name="SMB Command - COPY - Response"
    overload_fields = {SMB_Header:{"Command":0x29,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("Count",0),
                   FieldLenField("ByteCount",None,length_of="ErrorFileName",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("ErrorFileName","")]


class SMB_COM_MOVE_Req(SMB_COM): # obsolete (LANMAN1.0)
    name="SMB Command - MOVE - Request"
    overload_fields = {SMB_Header:{"Command":0x2A,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",3),
                   LEShortField("TID2",0),
                   BitField("OpenMode_Reserved1",0,6),
                   BitEnumField("OpenMode_Open",0,2,{0:"fail",2:"overwrite"}),
                   BitField("OpenMode_Reserved2",0,8),
                   LEFlagsField("Flags",0,16,smb_flags_COPY_Flags),
                   LEShortField("ByteCount",None),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("SourceFileName",""),
                   ByteField("BufferFormat2",4),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("DestFileName","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-9
            p = p[:7]+struct.pack("<H",l)+p[9:]
        p += pay
        return p

class SMB_COM_MOVE_Res(SMB_COM_COPY_Res): # obsolete (LANMAN1.0)
    name="SMB Command - MOVE - Response"
    overload_fields = {SMB_Header:{"Command":0x2A,"Flags":0x80}}


class SMB_COM_ECHO_Req(SMB_COM):
    name="SMB Command - ECHO - Request"
    overload_fields = {SMB_Header:{"Command":0x2B,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("EchoCount",0),
                   FieldLenField("ByteCount",None,length_of="Data",fmt="<H"),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.ByteCount)]

class SMB_COM_ECHO_Res(SMB_COM):
    name="SMB Command - ECHO - Response"
    overload_fields = {SMB_Header:{"Command":0x2B,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("SequenceNumber",0),
                   FieldLenField("ByteCount",None,length_of="Data",fmt="<H"),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.ByteCount)]


class SMB_COM_WRITE_AND_CLOSE_Req(SMB_COM):
    name="SMB Command - WRITE_AND_CLOSE - Request"
    overload_fields = {SMB_Header:{"Command":0x2C,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",6),
                   LEShortField("FID",0),
                   FieldLenField("CountOfBytesToWrite",None,length_of="Data",fmt="<H"),
                   LEIntField("WriteOffsetInBytes",0),
                   LETimeField("LastWriteTime",0),
                   ConditionalField(LEBitField("Reserved",0,32*3),
                                    lambda pkt:pkt.WordCount >= 12),
                   FieldLenField("ByteCount",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("Pad",0),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.CountOfBytesToWrite)]

class SMB_COM_WRITE_AND_CLOSE_Res(SMB_COM_WRITE_Res):
    name="SMB Command - WRITE_AND_CLOSE - Response"
    overload_fields = {SMB_Header:{"Command":0x2C,"Flags":0x80}}


class SMB_COM_OPEN_ANDX_Req(SMB_ANDX):
    name="SMB Command - OPEN_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x2D,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",15),
                   _smb_fields_AndX,
                   LEFlagsField("Flags",0,16,smb_flags_OPEN_ANDX_Flags),
                   _smb_fields_AccessMode,
                   LEFlagsField("SearchAttrs",0,16,SMB_FILE_ATTRIBUTES),
                   LEFlagsField("FileAttrs",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("CreationTime",0),
                   _smb_fields_OpenMode,
                   LEIntField("AllocationSize",0),
                   LEIntField("Timeout",0),
                   LEIntField("Reserved",0),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+pkt.getfieldlen("Pad")),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_OPEN_ANDX_Res(SMB_ANDX):
    name="SMB Command - OPEN_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x2D,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",15),
                   _smb_fields_AndX,
                   LEShortField("FID",0),
                   LEFlagsField("FileAttrs",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("LastWriteTime",0),
                   LEIntField("DataSize",0),
                   LEShortEnumField("GrantedAccess",0,smb_enum_GrantedAccess),
                   LEShortEnumField("ResourceType",0,smb_enum_ResourceType),
                   _smb_fields_SMB_NMPIPE_STATUS,
                   _smb_fields_OpenResults,
                   LEBitField("Reserved",0,16*3),
                   LEShortField("ByteCount",0)]

class SMB_COM_OPEN_ANDX_ResExtend(SMB_COM_OPEN_ANDX_Res):
    name="SMB Command - OPEN_ANDX - Extended Response"
    fields_desc = [ByteField("WordCount",19),
                   _smb_fields_AndX,
                   LEShortField("FID",0),
                   LEFlagsField("FileAttrs",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("LastWriteTime",0),
                   LEIntField("DataSize",0),
                   LEShortEnumField("GrantedAccess",0,smb_enum_GrantedAccess),
                   LEShortEnumField("ResourceType",0,smb_enum_ResourceType),
                   _smb_fields_SMB_NMPIPE_STATUS,
                   _smb_fields_OpenResults,
                   LEIntField("ServerFID",0),
                   LEShortField("Reserved",0),
                   LEFlagsField("MaximalAccessRights",0,32,ACCESS_MASK),
                   LEFlagsField("GuestMaximalAccessRights",0,32,ACCESS_MASK),
                   LEShortField("ByteCount",0)]


class SMB_COM_READ_ANDX_Req(SMB_ANDX):
    name="SMB Command - READ_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x2E,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",10),
                   _smb_fields_AndX,
                   LEShortField("FID",0),
                   LEIntField("Offset",0),
                   LEShortField("MaxCountOfBytesToReturn",0),
                   LEShortField("MinCountOfBytesToReturn",0),
                   LEIntField("Timeout_or_MaxCountHigh",0),
                   LEShortField("Remaining",0),
                   ConditionalField(LEIntField("OffsetHigh",0),
                                    lambda pkt:pkt.WordCount >= 12),
                   LEShortField("ByteCount",0)]

class SMB_COM_READ_ANDX_Res(SMB_ANDX):
    name="SMB Command - READ_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x2E,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",12),
                   _smb_fields_AndX,
                   LEShortField("Available",0),
                   LEShortField("DataCompactionMode",0),
                   LEShortField("Reserved1",0),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:x&0xFFFF),
                   LEShortField("DataOffset",None),
                   FieldLenField("DataLengthHigh",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:(x>>16)&0xFFFF),
                   LEBitField("Reserved2",0,16*4),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength-(pkt.DataLengthHigh<<16)),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength+(pkt.DataLengthHigh<<16))]
    def post_build(self, p, pay):
        if self.DataOffset is None:
            if self.getfieldlen("Data") > 0:
                offset = 32+27+self.getfieldlen("Padding")
            else:
                offset = 0
            p = p[:13]+struct.pack("<H",offset)+p[15:]
        if self.ByteCount is None:
            l = len(p)-27
            p = p[:25]+struct.pack("<H",l)+p[27:]
        return SMB_ANDX.post_build(self, p, pay)


class SMB_COM_WRITE_ANDX_Req(SMB_ANDX):
    name="SMB Command - WRITE_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x2F,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",12),
                   _smb_fields_AndX,
                   LEShortField("FID",0),
                   LEIntField("Offset",0),
                   LEIntField("Timeout",0),
                   LEFlagsField("WriteMode",0,16,smb_flags_WriteMode),
                   LEShortField("Remaining",0),
                   FieldLenField("DataLengthHigh",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:(x>>16)&0xFFFF),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:x&0xFFFF),
                   LEShortField("DataOffset",None),
                   ConditionalField(LEIntField("OffsetHigh",0),
                                    lambda pkt:pkt.WordCount >= 14),
                   LEShortField("ByteCount",None),
                   StrLenField("Padding","",
                               length_from=lambda pkt:pkt.ByteCount-pkt.DataLength-(pkt.DataLengthHigh<<16)),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength+(pkt.DataLengthHigh<<16))]
    def post_build(self, p, pay):
        if self.DataOffset is None:
            if self.getfieldlen("Data") > 0:
                offset = 32+27+self.getfieldlen("Padding")
                if self.WordCount >= 14:
                    offset += 4
            else:
                offset = 0
            p = p[:23]+struct.pack("<H",offset)+p[25:]
        if self.ByteCount is None:
            offset = 27
            if self.WordCount >= 14:
                offset += 4
            l = len(p)-offset
            p = p[:offset-2]+struct.pack("<H",l)+p[offset:]
        return SMB_ANDX.post_build(self, p, pay)

class SMB_COM_WRITE_ANDX_Res(SMB_ANDX):
    name="SMB Command - WRITE_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x2F,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",6),
                   _smb_fields_AndX,
                   LEShortField("Count",0),
                   LEShortField("Available",0),
                   LEShortField("CountHigh",0),
                   LEShortField("Reserved",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_CLOSE_AND_TREE_DISC_Req(SMB_COM_CLOSE_Req): # not implemented (partial in WinNT)
    name="SMB Command - CLOSE_AND_TREE_DISC - Request"
    overload_fields = {SMB_Header:{"Command":0x31,"Flags":0x00}}

class SMB_COM_CLOSE_AND_TREE_DISC_Res(SMB_COM_Null): # not implemented (partial in WinNT)
    name="SMB Command - CLOSE_AND_TREE_DISC - Response"
    overload_fields = {SMB_Header:{"Command":0x31,"Flags":0x80}}


class SMB_COM_TRANSACTION2_Req(SMB_TRANS):
    name="SMB Command - TRANSACTION2 - Request"
    base_len = 31
    overload_fields = {SMB_Header:{"Command":0x32,"Flags":0x00}}
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+14),
                   _smb_fields_TRANS_Req_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   ByteField("Reserved3",0),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-14)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("Name",""),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0),
                   StrLenField("Trans2_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+pkt.getfieldlen("Trans2_Parameters"))%2),
                   StrLenField("Trans2_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,21,25,1,19,3,23)
    def post_dissect(self, s):
        if hasattr(self, "Setup"):
            sub = self.Setup
            info = resume = None
            if type(sub) is list and self.SetupCount > 0:
                sub = sub[0]
            if hasattr(self, "InformationLevel"):
                info = self.InformationLevel
                if hasattr(self, "Param_Flags"):
                    resume = self.Param_Flags & 0x0004
            self.add_trans_db(0x32, self.SetupCount, sub, info, resume)
        return s

class SMB_COM_TRANSACTION2_Res(SMB_TRANS):
    name="SMB Command - TRANSACTION2 - Response"
    base_len = 23
    overload_fields = {SMB_Header:{"Command":0x32,"Flags":0x80}}
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+10),
                   _smb_fields_TRANS_Res_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   ByteField("Reserved2",0),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-10)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Trans2_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1+pkt.getfieldlen("Trans2_Parameters"))%2),
                   StrLenField("Trans2_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        if hasattr(self, "_trans_code"):
            if self.payload and hasattr(self.payload, "_level_code"):
                info = self.payload._level_code
            else:
                info = None
            self.add_trans_db(0x32, self._trans_code[0], self._trans_code[1], info)
        return self.post_build_trans(p,pay,9,15,1,7,3,13)

class SMB_COM_TRANSACTION2_ResI(SMB_COM_Null):
    name="SMB Command - TRANSACTION2 - Interim Response"
    overload_fields = {SMB_Header:{"Command":0x32,"Flags":0x80}}


class SMB_COM_TRANSACTION2_SECONDARY_Req(SMB_TRANS):
    name="SMB Command - TRANSACTION2_SECONDARY - Request"
    base_len = 19
    overload_fields = {SMB_Header:{"Command":0x33,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",9),
                   _smb_fields_TRANS_SECONDARY_count_offset,
                   LEShortField("FID",0xFFFF),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Trans2_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1+pkt.getfieldlen("Trans2_Parameters"))%2),
                   StrLenField("Trans2_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,7,13,1,5,3,11)

class SMB_COM_FIND_CLOSE2_Req(SMB_COM):
    name="SMB Command - FIND_CLOSE2 - Request"
    overload_fields = {SMB_Header:{"Command":0x34,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("SID",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_FIND_CLOSE2_Res(SMB_COM_Null):
    name="SMB Command - FIND_CLOSE2 - Response"
    overload_fields = {SMB_Header:{"Command":0x34,"Flags":0x80}}


# [XOPEN-SMB 15.3] http://www.opengroup.org/pubs/catalog/c209.htm
class SMB_COM_FIND_NOTIFY_CLOSE_Req(SMB_COM_FIND_CLOSE2_Req): # obsolete (X/Open 2.0)
    name="SMB Command - FIND_NOTIFY_CLOSE - Request"
    overload_fields = {SMB_Header:{"Command":0x35,"Flags":0x00}}

# [XOPEN-SMB 15.3] http://www.opengroup.org/pubs/catalog/c209.htm
class SMB_COM_FIND_NOTIFY_CLOSE_Res(SMB_COM_Null): # obsolete (X/Open 2.0)
    name="SMB Command - FIND_NOTIFY_CLOSE - Response"
    overload_fields = {SMB_Header:{"Command":0x35,"Flags":0x80}}


class SMB_COM_TREE_CONNECT_Req(SMB_COM):
    name="SMB Command - TREE_CONNECT - Request"
    overload_fields = {SMB_Header:{"Command":0x70,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",0),
                   LEShortField("ByteCount",None),
                   ByteField("BufferFormat1",4),
                   OEM_STRING_Field("Path",""),
                   ByteField("BufferFormat2",4),
                   OEM_STRING_Field("Password",""),
                   ByteField("BufferFormat3",4),
                   OEM_STRING_Field("Service","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-3
            p = p[:1]+struct.pack("<H",l)+p[3:]
        p += pay
        return p

class SMB_COM_TREE_CONNECT_Res(SMB_COM):
    name="SMB Command - TREE_CONNECT - Response"
    overload_fields = {SMB_Header:{"Command":0x70,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("MaxBufferSize",0),
                   LEShortField("TID",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_TREE_DISCONNECT_Req(SMB_COM_Null):
    name="SMB Command - TREE_DISCONNECT - Request"
    overload_fields = {SMB_Header:{"Command":0x71,"Flags":0x00}}

class SMB_COM_TREE_DISCONNECT_Res(SMB_COM_Null):
    name="SMB Command - TREE_DISCONNECT - Response"
    overload_fields = {SMB_Header:{"Command":0x71,"Flags":0x80}}


class SMB_COM_NEGOTIATE_Req(SMB_COM):
    name="SMB Command - NEGOTIATE - Request"
    overload_fields = {SMB_Header:{"Command":0x72,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",0),
                   FieldLenField("ByteCount",None,length_of="Dialects",fmt="<H"),
                   FieldListField("Dialects",[],SMBDialectField("Dialect",""),
                               length_from=lambda pkt:pkt.ByteCount)]

class SMB_COM_NEGOTIATE_Res(SMB_COM): # obsolete (Core) or unknown version
    name="SMB Command - NEGOTIATE - Response"
    overload_fields = {SMB_Header:{"Command":0x72,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("DialectIndex",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_NEGOTIATE_ResLANMAN(SMB_COM_NEGOTIATE_Res): # obsolete (LANMAN1.0)
    name="SMB Command - NEGOTIATE - LAN Manager Response"
    fields_desc = [ByteField("WordCount",13),
                   LEShortField("DialectIndex",0),
                   LEFlagsField("SecurityMode",0,16,smb_flags_SecurityMode),
                   LEShortField("MaxBufferSize",0),
                   LEShortField("MaxMpxCount",0),
                   LEShortField("MaxNumberVcs",0),
                   LEFlagsField("BlockMode",0,16,smb_flags_BlockMode),
                   LEIntField("SessionKey",0),
                   SMB_TIME_Field("ServerTime",None),
                   SMB_DATE_Field("ServerDate",None),
                   LESignedShortField("ServerTimeZone",0),
                   LEIntField("Reserved",0),
                   FieldLenField("ByteCount",None,length_of="EncryptionKey",fmt="<H"),
                   StrLenField("EncryptionKey","",
                               length_from=lambda pkt:pkt.ByteCount)]

class SMB_COM_NEGOTIATE_ResLANMAN21(SMB_COM_NEGOTIATE_Res): # obsolete (LANMAN2.1)
    name="SMB Command - NEGOTIATE - LAN Manager 2.1 Response"
    fields_desc = [ByteField("WordCount",13),
                   LEShortField("DialectIndex",0),
                   LEFlagsField("SecurityMode",0,16,smb_flags_SecurityMode),
                   LEShortField("MaxBufferSize",0),
                   LEShortField("MaxMpxCount",0),
                   LEShortField("MaxNumberVcs",0),
                   LEFlagsField("BlockMode",0,16,smb_flags_BlockMode),
                   LEIntField("SessionKey",0),
                   SMB_TIME_Field("ServerTime",None),
                   SMB_DATE_Field("ServerDate",None),
                   LESignedShortField("ServerTimeZone",0),
                   FieldLenField("EncryptionKeyLength",None,length_of="EncryptionKey",fmt="<H"),
                   LEShortField("Reserved",0),
                   LEShortField("ByteCount",None),
                   StrLenField("EncryptionKey","",
                               length_from=lambda pkt:pkt.EncryptionKeyLength),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("EncryptionKey")+1) % 2),
                   SMB_STRING_Field("DomainName","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-29
            p = p[:27]+struct.pack("<H",l)+p[29:]
        p += pay
        return p

class SMB_COM_NEGOTIATE_ResNTLM012(SMB_COM_NEGOTIATE_Res):
    name="SMB Command - NEGOTIATE - NT LM 0.12 Response"
    fields_desc = [ByteField("WordCount",17),
                   LEShortField("DialectIndex",0),
                   LEFlagsField("SecurityMode",0,8,smb_flags_SecurityMode_NT),
                   LEShortField("MaxMpxCount",0),
                   LEShortField("MaxNumberVcs",0),
                   LEIntField("MaxBufferSize",0),
                   LEIntField("MaxRawSize",0),
                   LEIntField("SessionKey",0),
                   LEFlagsField("Capabilities",0,32,smb_flags_Capabilities),
                   FILETIME_Field("SystemTime",None),
                   LESignedShortField("ServerTimeZone",0),
                   FieldLenField("ChallengeLength",None,length_of="Challenge",fmt="B"),
                   LEShortField("ByteCount",None),
                   StrLenField("Challenge","",
                               length_from=lambda pkt:pkt.ChallengeLength),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("Challenge")+1) % 2),
                   SMB_STRING_Field("DomainName",""),
                   SMB_STRING_Field("ServerName","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-37
            p = p[:35]+struct.pack("<H",l)+p[37:]
        p += pay
        return p

class SMB_COM_NEGOTIATE_ResNTLM012_ExtSec(SMB_COM_NEGOTIATE_Res):
    name="SMB Command - NEGOTIATE - NT LM 0.12 Extended Security Response"
    overload_fields = {SMB_Header:{"Command":0x72,"Flags":0x80,"Flags2":0x0800}}
    fields_desc = [ByteField("WordCount",17),
                   LEShortField("DialectIndex",0),
                   LEFlagsField("SecurityMode",0,8,smb_flags_SecurityMode_NT),
                   LEShortField("MaxMpxCount",0),
                   LEShortField("MaxNumberVcs",0),
                   LEIntField("MaxBufferSize",0),
                   LEIntField("MaxRawSize",0),
                   LEIntField("SessionKey",0),
                   LEFlagsField("Capabilities",0x80000000,32,smb_flags_Capabilities),
                   FILETIME_Field("SystemTime",None),
                   LESignedShortField("ServerTimeZone",0),
                   ByteField("ChallengeLength",0),
                   FieldLenField("ByteCount",None,length_of="SecurityBlob",fmt="<H",
                                 adjust=lambda pkt,x:x+16),
                   GUIDField("ServerGUID",""),
                   StrLenField("SecurityBlob","",
                               length_from=lambda pkt:pkt.ByteCount-16)]


class SMB_COM_SESSION_SETUP_ANDX_Req(SMB_ANDX):
    name="SMB Command - SESSION_SETUP_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x73,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",13),
                   _smb_fields_AndX,
                   LEShortField("MaxBufferSize",0),
                   LEShortField("MaxMpxCount",0),
                   LEShortField("VcNumber",0),
                   LEIntField("SessionKey",0),
                   FieldLenField("OEMPasswordLen",None,length_of="OEMPassword",fmt="<H"),
                   FieldLenField("UnicodePasswordLen",None,length_of="UnicodePassword",fmt="<H"),
                   LEIntField("Reserved",0),
                   LEFlagsField("Capabilities",0,32,smb_flags_Capabilities),
                   LEShortField("ByteCount",None),
                   StrLenField("OEMPassword","",
                               length_from=lambda pkt:pkt.OEMPasswordLen),
                   StrLenField("UnicodePassword","",
                               length_from=lambda pkt:pkt.UnicodePasswordLen),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("OEMPassword")+1) % 2),
                   SMB_STRING_Field("AccountName",""),
                   SMB_STRING_Field("PrimaryDomain",""),
                   SMB_STRING_Field("NativeOS",""),
                   SMB_STRING_Field("NativeLanMan","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-29
            p = p[:27]+struct.pack("<H",l)+p[29:]
        return SMB_ANDX.post_build(self, p, pay)

class SMB_COM_SESSION_SETUP_ANDX_Req_ExtSec(SMB_COM_SESSION_SETUP_ANDX_Req):
    name="SMB Command - SESSION_SETUP_ANDX - Extended Security Request"
    overload_fields = {SMB_Header:{"Command":0x73,"Flags":0x00,"Flags2":0x0800}}
    fields_desc = [ByteField("WordCount",12),
                   _smb_fields_AndX,
                   LEShortField("MaxBufferSize",0),
                   LEShortField("MaxMpxCount",0),
                   LEShortField("VcNumber",0),
                   LEIntField("SessionKey",0),
                   FieldLenField("SecurityBlobLength",None,length_of="SecurityBlob",fmt="<H"),
                   LEIntField("Reserved",0),
                   LEFlagsField("Capabilities",0,32,smb_flags_Capabilities),
                   LEShortField("ByteCount",None),
                   StrLenField("SecurityBlob","",
                               length_from=lambda pkt:pkt.SecurityBlobLength),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("SecurityBlob")+1) % 2),
                   SMB_STRING_Field("NativeOS",""),
                   SMB_STRING_Field("NativeLanMan","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-27
            p = p[:25]+struct.pack("<H",l)+p[27:]
        return SMB_ANDX.post_build(self, p, pay)
#XXX: smbtorture has a "PrimaryDomain" field at the end (and not in the response)

class SMB_COM_SESSION_SETUP_ANDX_Res(SMB_ANDX):
    name="SMB Command - SESSION_SETUP_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x73,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",3),
                   _smb_fields_AndX,
                   LEFlagsField("Action",0,16,smb_flags_Action),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("NativeOS",""),
                   SMB_STRING_Field("NativeLanMan",""),
                   SMB_STRING_Field("PrimaryDomain","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-9
            p = p[:7]+struct.pack("<H",l)+p[9:]
        return SMB_ANDX.post_build(self, p, pay)

class SMB_COM_SESSION_SETUP_ANDX_Res_ExtSec(SMB_COM_SESSION_SETUP_ANDX_Res):
    name="SMB Command - SESSION_SETUP_ANDX - Extended Security Response"
    overload_fields = {SMB_Header:{"Command":0x73,"Flags":0x80,"Flags2":0x0800}}
    fields_desc = [ByteField("WordCount",4),
                   _smb_fields_AndX,
                   LEFlagsField("Action",0,16,smb_flags_Action),
                   FieldLenField("SecurityBlobLength",None,length_of="SecurityBlob",fmt="<H"),
                   LEShortField("ByteCount",None),
                   StrLenField("SecurityBlob","",
                               length_from=lambda pkt:pkt.SecurityBlobLength),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("SecurityBlob")+1) % 2),
                   SMB_STRING_Field("NativeOS",""),
                   SMB_STRING_Field("NativeLanMan",""),
                   SMB_STRING_Field("PrimaryDomain","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-11
            p = p[:9]+struct.pack("<H",l)+p[11:]
        return SMB_ANDX.post_build(self, p, pay)
#XXX: smbtorture does not have the "PrimaryDomain" field (but wireshark detects it if present)


class SMB_COM_LOGOFF_ANDX_Req(SMB_ANDX):
    name="SMB Command - LOGOFF_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x74,"Flags":0x00}}

class SMB_COM_LOGOFF_ANDX_Res(SMB_ANDX):
    name="SMB Command - LOGOFF_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x74,"Flags":0x80}}


class SMB_COM_TREE_CONNECT_ANDX_Req(SMB_ANDX):
    name="SMB Command - TREE_CONNECT_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x75,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",4),
                   _smb_fields_AndX,
                   LEFlagsField("Flags",0,16,smb_flags_TRANSACTION_Flags),
                   FieldLenField("PasswordLength",None,length_of="Password",fmt="<H"),
                   LEShortField("ByteCount",None),
                   StrLenField("Password","",
                               length_from=lambda pkt:pkt.PasswordLength),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("Password")+1) % 2),
                   SMB_STRING_Field("Path",""),
                   OEM_STRING_Field("Service","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-11
            p = p[:9]+struct.pack("<H",l)+p[11:]
        return SMB_ANDX.post_build(self, p, pay)

class SMB_COM_TREE_CONNECT_ANDX_Res(SMB_ANDX):
    name="SMB Command - TREE_CONNECT_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x75,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",3),
                   _smb_fields_AndX,
                   LEFlagsField("OptionalSupport",0,16,smb_flags_OptionalSupport),
                   LEShortField("ByteCount",None),
                   OEM_STRING_Field("Service",""),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("Service")+1) % 2),
                   SMB_STRING_Field("NativeFileSystem","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-9
            p = p[:7]+struct.pack("<H",l)+p[9:]
        return SMB_ANDX.post_build(self, p, pay)

class SMB_COM_TREE_CONNECT_ANDX_ResExtend(SMB_ANDX):
    name="SMB Command - TREE_CONNECT_ANDX - Extended Response"
    overload_fields = {SMB_Header:{"Command":0x75,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",7),
                   _smb_fields_AndX,
                   BitField("OptionalSupport_Reserved1",0,2),
                   BitField("OptionalSupport_EXTENDED_SIGNATURES",0,1),
                   BitField("OptionalSupport_UNIQUE_FILE_NAME",0,1),
                   BitEnumField("OptionalSupport_CSC_MASK",0,2,{0:"CACHE_MANUAL_REINT",1:"CACHE_AUTO_REINT",
                                                                2:"CACHE_VDO",3:"NO_CACHING"}),
                   BitField("OptionalSupport_SHARE_IS_IN_DFS",0,1),
                   BitField("OptionalSupport_SUPPORT_SEARCH_BITS",0,1),
                   BitField("OptionalSupport_Reserved2",0,8),
                   LEFlagsField("MaximalShareAccessRights",0,32,ACCESS_MASK_directory),
                   LEFlagsField("GuestMaximalShareAccessRights",0,32,ACCESS_MASK_directory),
                   LEShortField("ByteCount",None),
                   OEM_STRING_Field("Service",""),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("Service")+1) % 2),
                   SMB_STRING_Field("NativeFileSystem","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-17
            p = p[:15]+struct.pack("<H",l)+p[17:]
        return SMB_ANDX.post_build(self, p, pay)


# [XOPEN-SMB 11.2] http://www.opengroup.org/pubs/catalog/c209.htm
class SMB_COM_SECURITY_PACKAGE_ANDX_Req(SMB_ANDX): # obsolete (LANMAN1.0)
    name="SMB Command - SECURITY_PACKAGE_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0x7E,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",4),
                   _smb_fields_AndX,
                   LEShortField("PackageType",0),
                   LEShortField("PackageCount",0), #TODO: count from PackageList
                   FieldLenField("ByteCount",None,length_of="PackageList",fmt="<H"),
                   StrLenField("PackageList","", #TODO: package list format
                               length_from=lambda pkt:pkt.ByteCount)]

# [XOPEN-SMB 11.2] http://www.opengroup.org/pubs/catalog/c209.htm
class SMB_COM_SECURITY_PACKAGE_ANDX_Res(SMB_ANDX): # obsolete (LANMAN1.0)
    name="SMB Command - SECURITY_PACKAGE_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0x7E,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",4),
                   _smb_fields_AndX,
                   LEShortField("Index",0),
                   FieldLenField("PackageArgLen",None,length_of="PackageArgs",fmt="<H"),
                   FieldLenField("ByteCount",None,length_of="PackageArgs",fmt="<H"),
                   StrLenField("PackageArgs","",
                               length_from=lambda pkt:pkt.PackageArgLen)]


class SMB_COM_QUERY_INFORMATION_DISK_Req(SMB_COM_Null):
    name="SMB Command - QUERY_INFORMATION_DISK - Request"
    overload_fields = {SMB_Header:{"Command":0x80,"Flags":0x00}}

class SMB_COM_QUERY_INFORMATION_DISK_Res(SMB_COM):
    name="SMB Command - QUERY_INFORMATION_DISK - Response"
    overload_fields = {SMB_Header:{"Command":0x80,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",5),
                   LEShortField("TotalUnits",0),
                   LEShortField("BlocksPerUnit",0),
                   LEShortField("BlockSize",0),
                   LEShortField("FreeUnits",0),
                   LEShortField("Reserved",0),
                   LEShortField("ByteCount",0)]


class SMB_COM_SEARCH_Req(SMB_COM):
    name="SMB Command - SEARCH - Request"
    overload_fields = {SMB_Header:{"Command":0x81,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("MaxCount",0),
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES_SEARCH),
                   LEShortField("ByteCount",None),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("FileName",""),
                   ByteField("BufferFormat2",5),
                   LEShortEnumField("ResumeKeyLength",0,smb_enum_ResumeKeyLength),
                   ConditionalField(ByteField("ResumeKey_Reserved",0),
                                    lambda pkt:pkt.ResumeKeyLength >= 21),
                   ConditionalField(StrFixedLenField("ResumeKey_ServerState","",16),
                                    lambda pkt:pkt.ResumeKeyLength >= 21),
                   ConditionalField(StrFixedLenField("ResumeKey_ClientState","",4),
                                    lambda pkt:pkt.ResumeKeyLength >= 21)]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-7
            p = p[:5]+struct.pack("<H",l)+p[7:]
        p += pay
        return p

class SMB_COM_SEARCH_Res(SMB_COM):
    name="SMB Command - SEARCH - Response"
    overload_fields = {SMB_Header:{"Command":0x81,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   FieldLenField("Count",None,count_of="DirectoryInformationData",fmt="<H"),
                   FieldLenField("ByteCount",None,length_of="DirectoryInformationData",fmt="<H",
                                 adjust=lambda pkt,x:x+3),
                   ByteField("BufferFormat",5),
                   FieldLenField("DataLength",None,length_of="DirectoryInformationData",fmt="<H"),
                   PacketListField("DirectoryInformationData",[],SMB_Directory_Information,
                                   count_from=lambda pkt:pkt.Count)]


class SMB_COM_FIND_Req(SMB_COM_SEARCH_Req):
    name="SMB Command - FIND - Request"
    overload_fields = {SMB_Header:{"Command":0x82,"Flags":0x00}}

class SMB_COM_FIND_Res(SMB_COM_SEARCH_Res):
    name="SMB Command - FIND - Response"
    overload_fields = {SMB_Header:{"Command":0x82,"Flags":0x80}}


class SMB_COM_FIND_UNIQUE_Req(SMB_COM):
    name="SMB Command - FIND_UNIQUE - Request"
    overload_fields = {SMB_Header:{"Command":0x83,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("MaxCount",0),
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES_SEARCH),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+4),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("FileName",""),
                   ByteField("BufferFormat2",5),
                   LEShortField("ResumeKeyLength",0)]

class SMB_COM_FIND_UNIQUE_Res(SMB_COM_SEARCH_Res):
    name="SMB Command - FIND_UNIQUE - Response"
    overload_fields = {SMB_Header:{"Command":0x83,"Flags":0x80}}


class SMB_COM_FIND_CLOSE_Req(SMB_COM):
    name="SMB Command - FIND_CLOSE - Request"
    overload_fields = {SMB_Header:{"Command":0x84,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("MaxCount",0),
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES_SEARCH),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H",
                                 adjust=lambda pkt,x:x+25),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("FileName",""),
                   ByteField("BufferFormat2",5),
                   LEShortField("ResumeKeyLength",21),
                   ByteField("ResumeKey_Reserved",0),
                   StrFixedLenField("ResumeKey_ServerState","",16),
                   StrFixedLenField("ResumeKey_ClientState","",4)]

class SMB_COM_FIND_CLOSE_Res(SMB_COM):
    name="SMB Command - FIND_CLOSE - Response"
    overload_fields = {SMB_Header:{"Command":0x84,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",1),
                   FieldLenField("Count",0),
                   LEShortField("ByteCount",3),
                   ByteField("BufferFormat",5),
                   LEShortField("DataLength",0)]


class SMB_COM_NT_TRANSACT_Req(SMB_TRANS):
    name="SMB Command - NT_TRANSACT - Request"
    base_len = 41
    overload_fields = {SMB_Header:{"Command":0xA0,"Flags":0x00}}
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+19),
                   _smb_fields_NT_TRANSACT_Req_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   XLEShortEnumField("Function",0,smb_nttrans_codes),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-19)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("NT_Trans_Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+pkt.getfieldlen("NT_Trans_Parameters")+1)%2),
                   StrLenField("NT_Trans_Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,24,32,4,20,8,28,longfld=True)
    def post_dissect(self, s):
        self.add_trans_db(0xA0, self.SetupCount, self.Function)
        return s

class SMB_COM_NT_TRANSACT_Res(SMB_TRANS):
    name="SMB Command - NT_TRANSACT - Response"
    base_len = 39
    overload_fields = {SMB_Header:{"Command":0xA0,"Flags":0x80}}
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+18),
                   _smb_fields_NT_TRANSACT_Res_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-18)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+pkt.getfieldlen("Parameters")+1)%2),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        if hasattr(self, "_trans_code"):
            self.add_trans_db(0xA0, self._trans_code[0], self._trans_code[1])
        return self.post_build_trans(p,pay,16,28,4,12,8,24,longfld=True)

class SMB_COM_NT_TRANSACT_ResI(SMB_COM_Null):
    name="SMB Command - NT_TRANSACT - Interim Response"
    overload_fields = {SMB_Header:{"Command":0xA0,"Flags":0x80}}


class SMB_COM_NT_TRANSACT_SECONDARY_Req(SMB_TRANS):
    name="SMB Command - NT_TRANSACT_SECONDARY - Request"
    base_len = 39
    overload_fields = {SMB_Header:{"Command":0xA1,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",18),
                   _smb_fields_NT_TRANSACT_Res_count_offset,
                   ByteField("Reserved2",0),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   StrLenField("Parameters","",
                               length_from=lambda pkt:pkt.ParameterCount),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+pkt.getfieldlen("Parameters")+1)%2),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]
    def post_build(self, p, pay):
        return self.post_build_trans(p,pay,16,28,4,12,8,24,longfld=True)


class SMB_COM_NT_CREATE_ANDX_Req(SMB_ANDX):
    name="SMB Command - NT_CREATE_ANDX - Request"
    overload_fields = {SMB_Header:{"Command":0xA2,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",24),
                   _smb_fields_AndX,
                   ByteField("Reserved",0),
                   FieldLenField("NameLength",None,length_of="FileName",fmt="<H"),
                   LEFlagsField("Flags",0,32,smb_flags_NT_CREATE_Flags),
                   LEIntField("RootDirectoryFID",0),
                   LEFlagsField("DesiredAccess",0,32,ACCESS_MASK),
                   LESignedLongField("AllocationSize",0),
                   LEFlagsField("ExtFileAttributes",0,32,SMB_EXT_FILE_ATTR),
                   LEFlagsField("ShareAccess",0,32,smb_flags_ShareAccess),
                   LEIntEnumField("CreateDisposition",0,smb_enum_CreateDisposition),
                   LEFlagsField("CreateOptions",0,32,smb_flags_CreateOptions),
                   LEIntEnumField("ImpersonationLevel",0,smb_enum_ImpersonationLevel),
                   LEFlagsField("SecurityFlags",0,8,smb_flags_SecurityFlags),
                   FieldLenField("ByteCount",None,length_of="FileName",fmt="<H"),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("FileName","")]

class SMB_COM_NT_CREATE_ANDX_Res(SMB_ANDX):
    name="SMB Command - NT_CREATE_ANDX - Response"
    overload_fields = {SMB_Header:{"Command":0xA2,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",34),
                   _smb_fields_AndX,
                   ByteEnumField("OpLockLevel",0,smb_enum_OpLockLevel),
                   LEShortField("FID",0),
                   LEIntEnumField("CreationAction",0,smb_enum_CreateDisposition),
                   _smb_fields_FILE_BASIC_INFO,
                   LESignedLongField("AllocationSize",0),
                   LESignedLongField("EndOfFile",0),
                   LEShortEnumField("ResourceType",0,smb_enum_ResourceType),
                   _smb_fields_SMB_NMPIPE_STATUS,
                   ByteEnumField("Directory",0,enum_BOOLEAN),
                   LEShortField("ByteCount",0)]

class SMB_COM_NT_CREATE_ANDX_ResExtend(SMB_COM_NT_CREATE_ANDX_Res):
    name="SMB Command - NT_CREATE_ANDX - Extended Response"
    fields_desc =([ByteField("WordCount",50), #NOTE: Windows incorrectly sets this to 42
                   _smb_fields_AndX,
                   ByteEnumField("OpLockLevel",0,smb_enum_OpLockLevel),
                   LEShortField("FID",0),
                   LEIntEnumField("CreationAction",0,smb_enum_CreateDisposition),
                   _smb_fields_FILE_BASIC_INFO,
                   LESignedLongField("AllocationSize",0),
                   LESignedLongField("EndOfFile",0),
                   LEShortEnumField("ResourceType",0,smb_enum_ResourceType)] +
                  [ConditionalField(fld,lambda pkt:pkt.ResourceType in [1,2])
                   for fld in _smb_fields_SMB_NMPIPE_STATUS.fields_desc] +
                  [ConditionalField(LEFlagsField("FileStatusFlags",0,16,smb_flags_FileStatusFlags),
                                    lambda pkt:pkt.ResourceType not in [1,2]),
                   ByteEnumField("Directory",0,enum_BOOLEAN),
                   GUIDField("VolumeGUID",""),
                   LELongField("FileId",0),
                   LEFlagsField("MaximalAccessRights",0,32,ACCESS_MASK),
                   LEFlagsField("GuestMaximalAccessRights",0,32,ACCESS_MASK),
                   LEShortField("ByteCount",0)])


class SMB_COM_NT_CANCEL_Req(SMB_COM_Null):
    name="SMB Command - NT_CANCEL - Request"
    overload_fields = {SMB_Header:{"Command":0xA4,"Flags":0x00}}


class SMB_COM_NT_RENAME_Req(SMB_COM):
    name="SMB Command - NT_RENAME - Request"
    overload_fields = {SMB_Header:{"Command":0xA5,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",4),
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   XLEShortEnumField("InformationLevel",0x0103,{0x0103:"SET_LINK_INFO",0x0104:"RENAME_FILE",
                                                                0x0105:"MOVE_FILE"}),
                   LEIntField("Reserved",0),
                   LEShortField("ByteCount",None),
                   ByteField("BufferFormat1",4),
                   SMB_STRING_Field("OldFileName",""),
                   ByteField("BufferFormat2",4),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_STRING_Field("NewFileName","")]
    def post_build(self, p, pay):
        if self.ByteCount is None:
            l = len(p)-11
            p = p[:9]+struct.pack("<H",l)+p[11:]
        p += pay
        return p

class SMB_COM_NT_RENAME_Res(SMB_COM_Null):
    name="SMB Command - NT_RENAME - Response"
    overload_fields = {SMB_Header:{"Command":0xA5,"Flags":0x80}}


class SMB_COM_OPEN_PRINT_FILE_Req(SMB_COM):
    name="SMB Command - OPEN_PRINT_FILE - Request"
    overload_fields = {SMB_Header:{"Command":0xC0,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("SetupLength",0),
                   LEShortEnumField("Mode",0,{0:"Text",1:"Binary"}),
                   FieldLenField("ByteCount",None,length_of="Identifier",fmt="<H",
                                 adjust=lambda pkt,x:x+1),
                   ByteField("BufferFormat",4),
                   SMB_STRING_Field("Identifier","")]

class SMB_COM_OPEN_PRINT_FILE_Res(SMB_COM_CREATE_Res):
    name="SMB Command - OPEN_PRINT_FILE - Response"
    overload_fields = {SMB_Header:{"Command":0xC0,"Flags":0x80}}


class SMB_COM_WRITE_PRINT_FILE_Req(SMB_COM):
    name="SMB Command - WRITE_PRINT_FILE - Request"
    overload_fields = {SMB_Header:{"Command":0xC1,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",1),
                   LEShortField("FID",0),
                   FieldLenField("ByteCount",None,length_of="Data",fmt="<H",
                                 adjust=lambda pkt,x:x+3),
                   ByteField("BufferFormat",1),
                   FieldLenField("DataLength",None,length_of="Data",fmt="<H"),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataLength)]

class SMB_COM_WRITE_PRINT_FILE_Res(SMB_COM_Null):
    name="SMB Command - WRITE_PRINT_FILE - Response"
    overload_fields = {SMB_Header:{"Command":0xC1,"Flags":0x80}}


class SMB_COM_CLOSE_PRINT_FILE_Req(SMB_COM_CREATE_Res):
    name="SMB Command - CLOSE_PRINT_FILE - Request"
    overload_fields = {SMB_Header:{"Command":0xC2,"Flags":0x00}}

class SMB_COM_CLOSE_PRINT_FILE_Res(SMB_COM_Null):
    name="SMB Command - CLOSE_PRINT_FILE - Response"
    overload_fields = {SMB_Header:{"Command":0xC2,"Flags":0x80}}


class SMB_COM_GET_PRINT_QUEUE_Req(SMB_COM): # obsolete (Core)
    name="SMB Command - GET_PRINT_QUEUE - Request"
    overload_fields = {SMB_Header:{"Command":0xC3,"Flags":0x00}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("MaxCount",0),
                   LEShortField("StartIndex",0),
                   LEShortField("ByteCount",0)]

class SMB_COM_GET_PRINT_QUEUE_Res(SMB_COM): # obsolete (Core)
    name="SMB Command - GET_PRINT_QUEUE - Response"
    overload_fields = {SMB_Header:{"Command":0xC3,"Flags":0x80}}
    fields_desc = [ByteField("WordCount",2),
                   LEShortField("Count",0), #TODO: count from QueueElements
                   LEShortField("RestartIndex",0),
                   FieldLenField("ByteCount",None,length_of="QueueElements",fmt="<H"),
                   StrLenField("QueueElements","", #TODO: queue element list format
                               length_from=lambda pkt:pkt.ByteCount)]


############################### SMB Transactions ###############################

class SMB_TRANS_SET_NMPIPE_STATE_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_SET_NMPIPE_STATE - Request"
    Subcommand = 0x0001
    fields_desc = [_smb_fields_TRANS_Req_HDR_with_fid,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0),
                   LEFlagsField("PipeState",0,16,smb_flags_PipeState)]

class SMB_TRANS_SET_NMPIPE_STATE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_SET_NMPIPE_STATE - Response"
    _trans_code = (2,0x0001)
    fields_desc = [_smb_fields_TRANS_Res_HDR]


class SMB_TRANS_RAW_READ_NMPIPE_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_RAW_READ_NMPIPE - Request"
    Subcommand = 0x0011
    fields_desc = [_smb_fields_TRANS_Req_HDR_with_fid]

class SMB_TRANS_RAW_READ_NMPIPE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_RAW_READ_NMPIPE - Response"
    _trans_code = (2,0x0011)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1),
                   StrLenField("BytesRead","",
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_TRANS_QUERY_NMPIPE_STATE_Req(SMB_TRANS_RAW_READ_NMPIPE_Req):
    name="SMB Trans - TRANS_QUERY_NMPIPE_STATE - Request"
    Subcommand = 0x0021

class SMB_TRANS_QUERY_NMPIPE_STATE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_QUERY_NMPIPE_STATE - Response"
    _trans_code = (2,0x0021)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   _smb_fields_SMB_NMPIPE_STATUS]


class SMB_TRANS_QUERY_NMPIPE_INFO_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_QUERY_NMPIPE_INFO - Request"
    Subcommand = 0x0022
    fields_desc = [_smb_fields_TRANS_Req_HDR_with_fid,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0),
                   LEShortField("Level",1)]

class SMB_TRANS_QUERY_NMPIPE_INFO_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_QUERY_NMPIPE_INFO - Response"
    _trans_code = (2,0x0022)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1), #XXX: pad here or before string?
                   LEShortField("OutputBufferSize",0),
                   LEShortField("InputBufferSize",0),
                   ByteField("MaximumInstances",0),
                   ByteField("CurrentInstances",0),
                   FieldLenField("PipeNameLength",None,length_of="PipeName",fmt="B"),
                   SMB_STRING_Field("PipeName","")]


class SMB_TRANS_PEEK_NMPIPE_Req(SMB_TRANS_RAW_READ_NMPIPE_Req):
    name="SMB Trans - TRANS_PEEK_NMPIPE - Request"
    Subcommand = 0x0023

class SMB_TRANS_PEEK_NMPIPE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_PEEK_NMPIPE - Response"
    _trans_code = (2,0x0023)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("ReadDataAvailable",0),
                   LEShortField("MessageBytesLength",0),
                   LEShortEnumField("NamedPipeState",0,{1:"disconnected",2:"listening",
                                                        3:"okay",4:"closed"}),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2),
                   StrLenField("BytesRead","",
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_TRANS_TRANSACT_NMPIPE_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_TRANSACT_NMPIPE - Request"
    Subcommand = 0x0026
    fields_desc = [_smb_fields_TRANS_Req_HDR_with_fid,
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   StrLenField("WriteData","",
                               length_from=lambda pkt:pkt.DataCount)]
#XXX: SNIA 3.15.4.10 "If NAME is \PIPE\LANMAN, this is a server API request"

class SMB_TRANS_TRANSACT_NMPIPE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_TRANSACT_NMPIPE - Response"
    _trans_code = (2,0x0026)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1),
                   StrLenField("ReadData","",
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_TRANS_RAW_WRITE_NMPIPE_Req(SMB_TRANS_TRANSACT_NMPIPE_Req):
    name="SMB Trans - TRANS_RAW_WRITE_NMPIPE - Request"
    Subcommand = 0x0031

class SMB_TRANS_RAW_WRITE_NMPIPE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_RAW_WRITE_NMPIPE - Response"
    _trans_code = (2,0x0031)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0),
                   LEShortField("BytesWritten",0)]


class SMB_TRANS_READ_NMPIPE_Req(SMB_TRANS_RAW_READ_NMPIPE_Req):
    name="SMB Trans - TRANS_READ_NMPIPE - Request"
    Subcommand = 0x0036

class SMB_TRANS_READ_NMPIPE_Res(SMB_TRANS_TRANSACT_NMPIPE_Res):
    name="SMB Trans - TRANS_READ_NMPIPE - Response"
    _trans_code = (2,0x0036)


class SMB_TRANS_WRITE_NMPIPE_Req(SMB_TRANS_TRANSACT_NMPIPE_Req):
    name="SMB Trans - TRANS_WRITE_NMPIPE - Request"
    Subcommand = 0x0037

class SMB_TRANS_WRITE_NMPIPE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_WRITE_NMPIPE - Response"
    _trans_code = (2,0x0037)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=0),
                   LEShortField("BytesWritten",0)]


class SMB_TRANS_WAIT_NMPIPE_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_WAIT_NMPIPE - Request"
    Subcommand = 0x0053
    fields_desc = [_smb_fields_TRANS_Req_HDR_with_priority]

class SMB_TRANS_WAIT_NMPIPE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_WAIT_NMPIPE - Response"
    _trans_code = (2,0x0053)
    fields_desc = [_smb_fields_TRANS_Res_HDR] #TODO: verify fields


class SMB_TRANS_CALL_NMPIPE_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_CALL_NMPIPE - Request"
    Subcommand = 0x0054
    fields_desc = [_smb_fields_TRANS_Req_HDR_with_priority,
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   StrLenField("WriteData","",
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_TRANS_CALL_NMPIPE_Res(SMB_TRANS_TRANSACT_NMPIPE_Res):
    name="SMB Trans - TRANS_CALL_NMPIPE - Response"
    _trans_code = (2,0x0054)


class SMB_TRANS_MAILSLOT_WRITE_Req(SMB_COM_TRANSACTION_Req):
    name="SMB Trans - TRANS_MAILSLOT_WRITE - Request"
    fields_desc = [ByteField("WordCount",17),
                   _smb_fields_TRANS_Req_count_offset,
                   ByteField("SetupCount",3),
                   ByteField("Reserved3",0),
                   XLEShortEnumField("MailSlotOpcode",0x0001,{0x0001:"TRANS_MAILSLOT_WRITE"}),
                   LEShortField("Priority",0),
                   LEShortEnumField("Class",1,{1:"Class 1",2:"Class 2"}),
                   LEShortField("ByteCount",None),
                   OEM_STRING_Field("MailslotName","\\MAILSLOT\\"), #XXX: can this be unicode? 
                   SMBUnicodePadField("Pad2","",padtype=2,padlen=0),
                   StrLenField("Databytes","",
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_TRANS_MAILSLOT_WRITE_Res(SMB_COM_TRANSACTION_Res):
    name="SMB Trans - TRANS_MAILSLOT_WRITE - Response"
    _trans_code = (3,0x0001)
#TODO: format?


class SMB_TRANS2_OPEN2_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_OPEN2 - Request"
    Setup = 0x0000
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEFlagsField("Param_Flags",0,16,smb_flags_TRANS2_OPEN2_Flags),
                   _smb_fields_AccessMode,
                   LEShortField("Param_Reserved1",0),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("CreationTime",0), #XXX: right format?
                   _smb_fields_OpenMode,
                   LEIntField("AllocationSize",0),
                   LEBitField("Param_Reserved",0,16*5),
                   SMB_STRING_Field("FileName",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   _smb_fields_SMB_FEA_LIST]

class SMB_TRANS2_OPEN2_Res(SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_OPEN2 - Response"
    _trans_code = (1,0x0000)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("FID",0),
                   LEFlagsField("FileAttributes",0,16,SMB_FILE_ATTRIBUTES),
                   LETimeField("CreationTime",0),
                   LEIntField("FileDataSize",0),
                   _smb_fields_AccessMode,
                   LEShortEnumField("ResourceType",0,smb_enum_ResourceType),
                   _smb_fields_SMB_NMPIPE_STATUS,
                   BitField("ActionTaken_Reserved1",0,6),
                   BitEnumField("ActionTaken_OpenResult",0,2,smb_enum_OpenResult),
                   BitField("ActionTaken_LockStatus",0,1),
                   BitField("ActionTaken_Reserved2",0,7),
                   LEIntField("Param_Reserved",0),
                   LEShortField("ExtendedAttributeErrorOffset",0),
                   LEIntField("ExtendedAttributeLength",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2)]


class SMB_TRANS2_FIND_FIRST2_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_FIND_FIRST2 - Request"
    Setup = 0x0001
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES_SEARCH),
                   LEShortField("SearchCount",0),
                   LEFlagsField("Param_Flags",0,16,smb_flags_TRANS2_FIND_Flags),
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_find_codes),
                   XLEIntEnumField("SearchStorageType",0x00000001,{0x00000001:"DIRECTORY_FILE",
                                                                   0x00000040:"NON_DIRECTORY_FILE"}),
                   SMB_STRING_Field("FileName",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   _smb_fields_SMB_GEA_LIST]

class SMB_TRANS2_FIND_FIRST2_Res(_SMBGuessPayload_INFO_FIND,SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_FIND_FIRST2 - Response"
    _trans_code = (1,0x0001)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("SID",0),
                   LEShortField("SearchCount",0),
                   LEShortField("EndOfSearch",0),
                   LEShortField("EaErrorOffset",0),
                   LEShortField("LastNameOffset",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2)]


class SMB_TRANS2_FIND_NEXT2_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_FIND_NEXT2 - Request"
    Setup = 0x0002
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEShortField("SID",0),
                   LEShortField("SearchCount",0),
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_find_codes),
                   LEIntField("ResumeKey",0),
                   LEFlagsField("Param_Flags",0,16,smb_flags_TRANS2_FIND_Flags),
                   SMB_STRING_Field("FileName",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   _smb_fields_SMB_GEA_LIST]

class SMB_TRANS2_FIND_NEXT2_Res(_SMBGuessPayload_INFO_FIND,SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_FIND_NEXT2 - Response"
    _trans_code = (1,0x0002)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("SearchCount",0),
                   LEShortField("EndOfSearch",0),
                   LEShortField("EaErrorOffset",0),
                   LEShortField("LastNameOffset",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2)]


class SMB_TRANS2_QUERY_FS_INFORMATION_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_QUERY_FS_INFORMATION - Request"
    Setup = 0x0003
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_queryfs_codes)]

class SMB_TRANS2_QUERY_FS_INFORMATION_Res(_SMBGuessPayload_INFO_QUERYFS,SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_QUERY_FS_INFORMATION - Response"
    _trans_code = (1,0x0003)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1)]


class SMB_TRANS2_SET_FS_INFORMATION_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_SET_FS_INFORMATION - Request"
    Setup = 0x0004
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEShortField("FID",0),
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_set_codes),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:pkt.getfieldlen("Pad1")%2),
                   StrLenField("Trans2_Data","", #XXX: InformationLevel format?
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_TRANS2_SET_FS_INFORMATION_Res(SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_SET_FS_INFORMATION - Response"
    _trans_code = (1,0x0004)
    fields_desc = [_smb_fields_TRANS_Res_HDR]


class SMB_TRANS2_QUERY_PATH_INFORMATION_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_QUERY_PATH_INFORMATION - Request"
    Setup = 0x0005
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_query_codes),
                   LEIntField("Param_Reserved",0),
                   SMB_STRING_Field("FileName",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   _smb_fields_SMB_GEA_LIST]

class SMB_TRANS2_QUERY_PATH_INFORMATION_Res(_SMBGuessPayload_INFO_QUERY,SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_QUERY_PATH_INFORMATION - Response"
    _trans_code = (1,0x0005)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   ConditionalField(LEShortField("EaErrorOffset",0),
                                    lambda pkt:pkt.ParameterCount > 0), #XXX: why is this missing sometimes?
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2)]


class SMB_TRANS2_SET_PATH_INFORMATION_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_SET_PATH_INFORMATION - Request"
    Setup = 0x0006
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_set_codes),
                   LEIntField("Param_Reserved",0),
                   SMB_STRING_Field("FileName",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0)]

class SMB_TRANS2_SET_PATH_INFORMATION_Res(SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_SET_PATH_INFORMATION - Response"
    _trans_code = (1,0x0006)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("EaErrorOffset",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:pkt.getfieldlen("Pad1")%2)]


class SMB_TRANS2_QUERY_FILE_INFORMATION_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_QUERY_FILE_INFORMATION - Request"
    Setup = 0x0007
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEShortField("FID",0),
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_query_codes)]

class SMB_TRANS2_QUERY_FILE_INFORMATION_Res(SMB_TRANS2_QUERY_PATH_INFORMATION_Res):
    name="SMB Trans - TRANS2_QUERY_FILE_INFORMATION - Response"
    _trans_code = (1,0x0007)


class SMB_TRANS2_SET_FILE_INFORMATION_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_SET_FILE_INFORMATION - Request"
    Setup = 0x0008
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEShortField("FID",0),
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_set_codes),
                   LEShortField("Param_Reserved",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:pkt.getfieldlen("Pad1")%2)]

class SMB_TRANS2_SET_FILE_INFORMATION_Res(SMB_TRANS2_SET_PATH_INFORMATION_Res):
    name="SMB Trans - TRANS2_SET_FILE_INFORMATION - Response"
    _trans_code = (1,0x0008)


class SMB_TRANS2_FIND_NOTIFY_FIRST_Req(SMB_COM_TRANSACTION2_Req): # obsolete (X/Open 2.0)
    name="SMB Trans - TRANS2_FIND_NOTIFY_FIRST - Request"
    Setup = 0x000B
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEFlagsField("SearchAttributes",0,16,SMB_FILE_ATTRIBUTES_SEARCH),
                   LEShortField("ChangeCount",0),
                   XLEShortEnumField("InformationLevel",0x0001,smb_info_find_codes),
                   LEIntField("Param_Reserved",0),
                   SMB_STRING_Field("PathSpec",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   _smb_fields_SMB_GEA_LIST]

class SMB_TRANS2_FIND_NOTIFY_FIRST_Res(_SMBGuessPayload_INFO_FIND,SMB_COM_TRANSACTION2_Res): # obsolete (X/Open 2.0)
    name="SMB Trans - TRANS2_FIND_NOTIFY_FIRST - Response"
    _trans_code = (1,0x000B)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("SID",0),
                   LEShortField("ChangeCount",0),
                   LEShortField("EaErrorOffset",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2)]


class SMB_TRANS2_FIND_NOTIFY_NEXT_Req(SMB_COM_TRANSACTION2_Req): # obsolete (X/Open 2.0)
    name="SMB Trans - TRANS2_FIND_NOTIFY_NEXT - Request"
    Setup = 0x000C
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEShortField("SID",0),
                   LEShortField("ChangeCount",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_TRANS2_FIND_NOTIFY_NEXT_Res(_SMBGuessPayload_INFO_FIND,SMB_COM_TRANSACTION2_Res): # obsolete (X/Open 2.0)
    name="SMB Trans - TRANS2_FIND_NOTIFY_NEXT - Response"
    _trans_code = (1,0x000C)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("ChangeCount",0),
                   LEShortField("EaErrorOffset",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2)]


class SMB_TRANS2_CREATE_DIRECTORY_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_CREATE_DIRECTORY - Request"
    Setup = 0x000D
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEIntField("Param_Reserved",0),
                   SMB_STRING_Field("DirectoryName",""),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   _smb_fields_SMB_FEA_LIST]

class SMB_TRANS2_CREATE_DIRECTORY_Res(SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_CREATE_DIRECTORY - Response"
    _trans_code = (1,0x000D)
    fields_desc = [_smb_fields_TRANS_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   LEShortField("EaErrorOffset",0)]


class SMB_TRANS2_GET_DFS_REFERRAL_Req(SMB_COM_TRANSACTION2_Req):
    name="SMB Trans - TRANS2_GET_DFS_REFERRAL - Request"
#    overload_fields = {SMB_Header:{"Command":0x32,"Flags":0x00,"Flags2":0x8000}}
    Setup = 0x0010
    fields_desc = [_smb_fields_TRANS2_Req_HDR,
                   LEShortField("MaxReferralLevel",1),
                   SMB_STRING_Field("RequestFileName","")]

class SMB_TRANS2_GET_DFS_REFERRAL_Res(SMB_COM_TRANSACTION2_Res):
    name="SMB Trans - TRANS2_GET_DFS_REFERRAL - Response"
    _trans_code = (1,0x0010)
    fields_desc = [_smb_fields_TRANS_Res_HDR, #XXX: verify setup count
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1),
                   StrLenField("Trans2_Data","", #TODO: RESP_GET_DFS_REFERRAL format
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_NT_TRANSACT_CREATE_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_CREATE - Request"
    Function = 0x0001
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup0,
                   LEFlagsField("Flags",0,32,smb_flags_NT_CREATE_Flags),
                   LEIntField("RootDirectoryFID",0),
                   LEFlagsField("DesiredAccess",0,32,ACCESS_MASK),
                   LESignedLongField("AllocationSize",0),
                   LEFlagsField("ExtFileAttributes",0,32,SMB_EXT_FILE_ATTR),
                   LEFlagsField("ShareAccess",0,32,smb_flags_ShareAccess),
                   LEIntEnumField("CreateDisposition",0,smb_enum_CreateDisposition),
                   LEFlagsField("CreateOptions",0,32,smb_flags_CreateOptions),
                   FieldLenField("SecurityDescriptorLength",None,length_of="SecurityDescriptor",fmt="<I"),
                   FieldLenField("EALength",None,length_of="ExtendedAttributes",fmt="<I"),
                   FieldLenField("NameLength",None,length_of="Name",fmt="<I"),
                   LEIntEnumField("ImpersonationLevel",0,smb_enum_ImpersonationLevel),
                   LEFlagsField("SecurityFlags",0,8,smb_flags_SecurityFlags),
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:pkt.getfieldlen("Pad1")%2),
                   SMB_UCHAR_LenField("Name","",
                                      length_from=lambda pkt:pkt.NameLength),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=0),
                   PacketLenField("SecurityDescriptor",Raw(),SECURITY_DESCRIPTOR,
                                  length_from=lambda pkt:pkt.SecurityDescriptorLength),
                   PacketListField("ExtendedAttributes",[],FILE_FULL_EA_INFORMATION,
                               length_from=lambda pkt:pkt.EALength)]

class SMB_NT_TRANSACT_CREATE_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_CREATE - Response"
    _trans_code = (0,0x0001)
    fields_desc = [_smb_fields_NT_TRANSACT_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   ByteEnumField("OpLockLevel",0,smb_enum_OpLockLevel),
                   ByteField("Param_Reserved",0),
                   LEShortField("FID",0),
                   LEIntEnumField("CreateAction",0,{0:"SUPERSEDE",1:"OPEN",
                                                    2:"CREATE",3:"OVERWRITE"}),
                   LEIntField("EAErrorOffset",0),
                   _smb_fields_FILE_BASIC_INFO,
                   LESignedLongField("AllocationSize",0),
                   LESignedLongField("EndOfFile",0),
                   LEShortEnumField("ResourceType",0,smb_enum_ResourceType),
                   _smb_fields_SMB_NMPIPE_STATUS,
                   ByteEnumField("Directory",0,enum_BOOLEAN)]


class SMB_NT_TRANSACT_IOCTL_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_IOCTL - Request"
    Function = 0x0002
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup4,
                   XLEIntEnumField("FunctionCode",0,fsctl_codes),
                   LEShortField("FID",0),
                   ByteEnumField("IsFctl",0,enum_BOOLEAN),
                   ByteEnumField("IsFlags",0,enum_BOOLEAN),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_NT_TRANSACT_IOCTL_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_IOCTL - Response"
    _trans_code = (0,0x0002)
    fields_desc = [FieldLenField("WordCount",None,length_of="Setup",fmt="B",
                                 adjust=lambda pkt,x:x/2+18),
                   _smb_fields_NT_TRANSACT_Res_count_offset,
                   FieldLenField("SetupCount",None,count_of="Setup",fmt="B"),
                   FieldListField("Setup",[],LEShortField("setup_word",0),
                                  length_from=lambda pkt:(pkt.WordCount-18)*2),
                   LEShortField("ByteCount",None),
                   SMBUnicodePadField("Pad2",None,padtype=2,padlen=1),
                   StrLenField("Data","",
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_NT_TRANSACT_SET_SECURITY_DESC_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_SET_SECURITY_DESC - Request"
    Function = 0x0003
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup0,
                   LEShortField("FID",0),
                   LEShortField("Param_Reserved",0),
                   LEFlagsField("SecurityInformation",0,32,smb_flags_SecurityInformation),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2),
                   PacketLenField("SecurityDescriptor",Raw(),SECURITY_DESCRIPTOR,
                                  length_from=lambda pkt:pkt.DataCount)]

class SMB_NT_TRANSACT_SET_SECURITY_DESC_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_SET_SECURITY_DESC - Response"
    _trans_code = (0,0x0003)
    fields_desc = [_smb_fields_NT_TRANSACT_Res_HDR]


class SMB_NT_TRANSACT_NOTIFY_CHANGE_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_NOTIFY_CHANGE - Request"
    Function = 0x0004
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup4,
                   LEFlagsField("CompletionFilter",0,32,smb_flags_CompletionFilter),
                   LEShortField("FID",0),
                   ByteEnumField("WatchTree",0,enum_BOOLEAN),
                   ByteField("Reserved",0),
                   LEShortField("ByteCount",0)]

class SMB_NT_TRANSACT_NOTIFY_CHANGE_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_NOTIFY_CHANGE - Response"
    _trans_code = (0,0x0004)
    fields_desc = [_smb_fields_NT_TRANSACT_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   PacketListField("FileNotifyInformation",[],SMB_FILE_NOTIFY_INFORMATION,
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_NT_TRANSACT_QUERY_SECURITY_DESC_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_QUERY_SECURITY_DESC - Request"
    Function = 0x0006
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup0,
                   LEShortField("FID",0),
                   LEShortField("Param_Reserved",0),
                   LEFlagsField("SecurityInformation",0,32,smb_flags_SecurityInformation)]

class SMB_NT_TRANSACT_QUERY_SECURITY_DESC_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_QUERY_SECURITY_DESC - Response"
    _trans_code = (0,0x0006)
    fields_desc = [_smb_fields_NT_TRANSACT_Res_HDR,
                   ConditionalField(SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                                    lambda pkt:pkt.ParameterCount >= 4),
                   ConditionalField(FieldLenField("SecurityDescriptorLength",None,length_of="SecurityDescriptor",fmt="<I"),
                                    lambda pkt:pkt.ParameterCount >= 4), #XXX: not in spec
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2),
                   PacketLenField("SecurityDescriptor",Raw(),SECURITY_DESCRIPTOR,
                                  length_from=lambda pkt:pkt.DataCount)]


class SMB_NT_TRANSACT_QUERY_QUOTA_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_QUERY_QUOTA - Request"
    Function = 0x0007
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup0,
                   LEShortField("FID",0),
                   ByteEnumField("ReturnSingleEntry",0,enum_BOOLEAN),
                   ByteEnumField("RestartScan",0,enum_BOOLEAN),
                   FieldLenField("SidListLength",None,length_of="SidList",fmt="<I"),
                   LEIntField("StartSidLength",0),
                   LEIntField("StartSidOffset",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2),
                   PacketListField("SidList",[],FILE_GET_QUOTA_INFORMATION,
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_NT_TRANSACT_QUERY_QUOTA_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_QUERY_QUOTA - Response"
    _trans_code = (0,0x0007)
    fields_desc = [_smb_fields_NT_TRANSACT_Res_HDR,
                   SMBUnicodePadField("Pad1",None,padtype=1,padlen=1),
                   FieldLenField("DataLength",None,length_of="QuotaInformation",fmt="<I"),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2),
                   PacketListField("QuotaInformation",[],FILE_QUOTA_INFORMATION,
                               length_from=lambda pkt:pkt.DataCount)]


class SMB_NT_TRANSACT_SET_QUOTA_Req(SMB_COM_NT_TRANSACT_Req):
    name="SMB Trans - NT_TRANSACT_SET_QUOTA - Request"
    Function = 0x0008
    fields_desc = [_smb_fields_NT_TRANSACT_Req_HDR_setup0,
                   LEShortField("FID",0),
                   SMBUnicodePadField("Pad2",None,padtype=2,
                                      padlen=lambda pkt:(pkt.getfieldlen("Pad1")+1)%2),
                   PacketListField("QuotaInformation",[],FILE_QUOTA_INFORMATION,
                               length_from=lambda pkt:pkt.DataCount)]

class SMB_NT_TRANSACT_SET_QUOTA_Res(SMB_COM_NT_TRANSACT_Res):
    name="SMB Trans - NT_TRANSACT_SET_QUOTA - Response"
    _trans_code = (0,0x0008)
    fields_desc = [_smb_fields_NT_TRANSACT_Res_HDR]


class SMB_NT_TRANSACT_CREATE2_Req(SMB_NT_TRANSACT_CREATE_Req):
    name="SMB Trans - NT_TRANSACT_CREATE2 - Request"
    Function = 0x0009

class SMB_NT_TRANSACT_CREATE2_Res(SMB_NT_TRANSACT_CREATE_Res):
    name="SMB Trans - NT_TRANSACT_CREATE2 - Response"
    _trans_code = (0,0x0009)


####################### SMB Information Level Structures #######################

class _SMB_INFO:
    def guess_payload_class(self, payload):
        if hasattr(self, "NextEntryOffset") and self.NextEntryOffset > 0:
            return self.__class__
        else:
            return Packet.guess_payload_class(self, payload)
    def post_build(self, p, pay):
        if hasattr(self, "NextEntryOffset") and self.NextEntryOffset is None:
            if isinstance(self.payload, _SMB_INFO):
                l = len(p)
            else:
                l = 0
            p = p[:0]+struct.pack("<I",l)+p[4:]
        return p+pay
    def is_unicode(self):
        if isinstance(self.underlayer, SMB_COM) or isinstance(self.underlayer, _SMB_INFO):
            return self.underlayer.is_unicode()
        return None


class SMB_SET_INFO_STANDARD(_SMB_INFO,Packet):
    name="SMB Info (SET) - SMB_INFO_STANDARD"
    fields_desc = [_smb_fields_date_time,
                   LEBitField("Reserved",0,8*10)]
#XXX: smbtorture missing Reserved bytes

class SMB_SET_INFO_SET_EAS(_SMB_INFO,Packet):
    name="SMB Info (SET) - SMB_INFO_SET_EAS"
    fields_desc = [_smb_fields_SMB_FEA_LIST]

class SMB_SET_FILE_BASIC_INFO(_SMB_INFO,Packet):
    name="SMB Info (SET) - SMB_SET_FILE_BASIC_INFO"
    fields_desc = [_smb_fields_FILE_BASIC_INFO,
                   LEIntField("Reserved",0)]

class SMB_SET_FILE_DISPOSITION_INFO(_SMB_INFO,Packet):
    name="SMB Info (SET) - SMB_SET_FILE_DISPOSITION_INFO"
    fields_desc = [ByteEnumField("DeletePending",0,enum_BOOLEAN)]

class SMB_SET_FILE_ALLOCATION_INFO(_SMB_INFO,Packet):
    name="SMB Info (SET) - SMB_SET_FILE_ALLOCATION_INFO"
    fields_desc = [LESignedLongField("AllocationSize",0)]

class SMB_SET_FILE_END_OF_FILE_INFO(_SMB_INFO,Packet):
    name="SMB Info (SET) - SMB_SET_FILE_END_OF_FILE_INFO"
    fields_desc = [LESignedLongField("EndOfFile",0)]


class SMB_QUERY_INFO_STANDARD(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_INFO_STANDARD"
    _level_code = 0x0001
    fields_desc = [_smb_fields_date_time,
                   LEIntField("FileDataSize",0),
                   LEIntField("AllocationSize",0),
                   LEFlagsField("Attributes",0,16,SMB_FILE_ATTRIBUTES)]

class SMB_QUERY_INFO_QUERY_EA_SIZE(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_INFO_QUERY_EA_SIZE"
    _level_code = 0x0002
    fields_desc = [SMB_QUERY_INFO_STANDARD,
                   LEIntField("EaSize",0)]

class SMB_QUERY_INFO_QUERY_EAS_FROM_LIST(SMB_SET_INFO_SET_EAS):
    name="SMB Info (QUERY) - SMB_QUERY_INFO_QUERY_EAS_FROM_LIST"
    _level_code = 0x0003

class SMB_QUERY_INFO_QUERY_ALL_EAS(SMB_SET_INFO_SET_EAS):
    name="SMB Info (QUERY) - SMB_QUERY_INFO_QUERY_ALL_EAS"
    _level_code = 0x0004

class SMB_QUERY_FILE_BASIC_INFO(SMB_SET_FILE_BASIC_INFO):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_BASIC_INFO"
    _level_code = 0x0101

class SMB_QUERY_FILE_STANDARD_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_STANDARD_INFO"
    _level_code = 0x0102
    fields_desc = [LESignedLongField("AllocationSize",0),
                   LESignedLongField("EndOfFile",0),
                   LEIntField("NumberOfLinks",0),
                   ByteEnumField("DeletePending",0,enum_BOOLEAN),
                   ByteEnumField("Directory",0,enum_BOOLEAN)]

class SMB_QUERY_FILE_EA_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_EA_INFO"
    _level_code = 0x0103
    fields_desc = [LEIntField("EaSize",0)]

class SMB_QUERY_FILE_NAME_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_NAME_INFO"
    _level_code = 0x0104
    fields_desc = [FieldLenField("FileNameLength",None,length_of="FileName",fmt="<I"),
                   UCHAR_LenField("FileName","",
                                  length_from=lambda pkt:pkt.FileNameLength)]

class SMB_QUERY_FILE_ALL_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_ALL_INFO"
    _level_code = 0x0107
    fields_desc = [_smb_fields_FILE_BASIC_INFO,
                   LEIntField("Reserved1",0),
                   SMB_QUERY_FILE_STANDARD_INFO,
                   LEShortField("Reserved2",0),
                   LEIntField("EaSize",0),
                   FieldLenField("FileNameLength",None,length_of="FileName",fmt="<I"),
                   UCHAR_LenField("FileName","",
                                  length_from=lambda pkt:pkt.FileNameLength)]

class SMB_QUERY_FILE_ALT_NAME_INFO(SMB_QUERY_FILE_NAME_INFO):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_ALT_NAME_INFO"
    _level_code = 0x0108

class SMB_QUERY_FILE_STREAM_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_STREAM_INFO"
    _level_code = 0x0109
    fields_desc = [LEIntField("NextEntryOffset",None),
                   FieldLenField("StreamNameLength",None,length_of="StreamName",fmt="<I"),
                   LESignedLongField("StreamSize",0),
                   LESignedLongField("StreamAllocationSize",0),
                   UCHAR_LenField("StreamName","::$DATA",
                                  length_from=lambda pkt:pkt.StreamNameLength)]

class SMB_QUERY_FILE_COMPRESSION_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY) - SMB_QUERY_FILE_COMPRESSION_INFO"
    _level_code = 0x010B
    fields_desc = [LESignedLongField("CompressedFileSize",0),
                   LEShortEnumField("CompressionFormat",0,{0:"NONE",1:"DEFAULT",2:"LZNT1"}),
                   ByteField("CompressionUnitShift",0),
                   ByteField("ChunkShift",0),
                   ByteField("ClusterShift",0),
                   LEBitField("Reserved",0,8*3)]


class SMB_FIND_INFO_STANDARD(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_INFO_STANDARD"
    _level_code = 0x0001
    fields_desc = [SMB_QUERY_INFO_STANDARD,
                   FieldLenField("FileNameLength",None,length_of="FileName",fmt="B"),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength)]
    def guess_payload_class(self, payload): #XXX: does not follow SearchCount value
        if len(payload) >= 23:
            return self.__class__
        else:
            return Raw

class SMB_FIND_INFO_STANDARD_Resume(SMB_FIND_INFO_STANDARD): #XXX: not detected
    name="SMB Info (FIND) - SMB_INFO_STANDARD (Resume)"
    fields_desc = [LEIntField("ResumeKey",0),
                   SMB_FIND_INFO_STANDARD]

class SMB_FIND_INFO_QUERY_EA_SIZE(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_INFO_QUERY_EA_SIZE"
    _level_code = 0x0002
    fields_desc = [SMB_QUERY_INFO_STANDARD,
                   LEIntField("EaSize",0),
                   FieldLenField("FileNameLength",None,length_of="FileName",fmt="B"),
                   SMBUnicodePadField("Pad",None,padlen=1),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength)]
    def guess_payload_class(self, payload): #XXX: does not follow SearchCount value
        if len(payload) >= 27:
            return self.__class__
        else:
            return Raw
#XXX: smbtorture seems to indicate a bug where the padding is added AFTER the filename field

class SMB_FIND_INFO_QUERY_EA_SIZE_Resume(SMB_FIND_INFO_QUERY_EA_SIZE): #XXX: not detected
    name="SMB Info (FIND) - SMB_INFO_QUERY_EA_SIZE (Resume)"
    fields_desc = [LEIntField("ResumeKey",0),
                   SMB_FIND_INFO_QUERY_EA_SIZE]

class SMB_FIND_INFO_QUERY_EAS_FROM_LIST(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_INFO_QUERY_EAS_FROM_LIST"
    _level_code = 0x0003
    fields_desc = [SMB_QUERY_INFO_STANDARD,
                   _smb_fields_SMB_FEA_LIST,
                   FieldLenField("FileNameLength",None,length_of="FileName",fmt="B"), #XXX: Windows NT sets this wrong
                   SMBUnicodePadField("Pad",None,
                                      padlen=lambda pkt:(pkt.getfieldlen("FEAList")+1) % 2),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength)]
    def guess_payload_class(self, payload): #XXX: does not follow SearchCount value
        if len(payload) >= 27:
            return self.__class__
        else:
            return Raw

class SMB_FIND_INFO_QUERY_EAS_FROM_LIST_Resume(SMB_FIND_INFO_QUERY_EAS_FROM_LIST): #XXX: not detected
    name="SMB Info (FIND) - SMB_INFO_QUERY_EAS_FROM_LIST (Resume)"
    fields_desc = [LEIntField("ResumeKey",0),
                   SMB_FIND_INFO_QUERY_EAS_FROM_LIST]

class SMB_FIND_FILE_DIRECTORY_INFO(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_FIND_FILE_DIRECTORY_INFO"
    _level_code = 0x0101
    fields_desc = [_smb_fields_FILE_DIRECTORY_INFO,
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength),
                   StrLenField("Pad","",
                               length_from=lambda pkt:pkt.NextEntryOffset-pkt.FileNameLength-64)]

class SMB_FIND_FILE_FULL_DIRECTORY_INFO(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_FIND_FILE_FULL_DIRECTORY_INFO"
    _level_code = 0x0102
    fields_desc = [_smb_fields_FILE_DIRECTORY_INFO,
                   LEIntField("EaSize",0),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength),
                   StrLenField("Pad","",
                               length_from=lambda pkt:pkt.NextEntryOffset-pkt.FileNameLength-68)]

class SMB_FIND_FILE_NAMES_INFO(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_FIND_FILE_NAMES_INFO"
    _level_code = 0x0103
    fields_desc = [LEIntField("NextEntryOffset",None),
                   LEIntField("FileIndex",0),
                   FieldLenField("FileNameLength",None,length_of="FileName",fmt="<I"),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength),
                   StrLenField("Pad","",
                               length_from=lambda pkt:pkt.NextEntryOffset-pkt.FileNameLength-12)]

class SMB_FIND_FILE_BOTH_DIRECTORY_INFO(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_FIND_FILE_BOTH_DIRECTORY_INFO"
    _level_code = 0x0104
    fields_desc = [_smb_fields_FILE_DIRECTORY_INFO,
                   LEIntField("EaSize",0),
                   FieldLenField("ShortNameLength",None,length_of="ShortName",fmt="B"),
                   ByteField("Reserved",0),
                   StrFixedLenField("ShortName","",24,codec="utf-16-le"),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength),
                   StrLenField("Pad","",
                               length_from=lambda pkt:pkt.NextEntryOffset-pkt.FileNameLength-94)]

class SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO"
    _level_code = 0x0105
    fields_desc = [_smb_fields_FILE_DIRECTORY_INFO,
                   LEIntField("EaSize",0),
                   LEIntField("Reserved",0), #XXX: not in spec
                   LELongField("FileId",0),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength),
                   StrLenField("Pad","",
                               length_from=lambda pkt:pkt.NextEntryOffset-pkt.FileNameLength-76)]

class SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO(_SMB_INFO,Packet):
    name="SMB Info (FIND) - SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO"
    _level_code = 0x0106
    fields_desc = [_smb_fields_FILE_DIRECTORY_INFO,
                   LEIntField("EaSize",0),
                   FieldLenField("ShortNameLength",None,length_of="ShortName",fmt="B"),
                   ByteField("Reserved",0),
                   StrFixedLenField("ShortName","",24,codec="utf-16-le"),
                   LEShortField("Reserved2",0),
                   LELongField("FileId",0),
                   SMB_UCHAR_LenField("FileName","",
                                      length_from=lambda pkt:pkt.FileNameLength),
                   StrLenField("Pad","",
                               length_from=lambda pkt:pkt.NextEntryOffset-pkt.FileNameLength-104)]


class SMB_QUERY_FS_INFO_ALLOCATION(_SMB_INFO,Packet):
    name="SMB Info (QUERY_FS) - SMB_QUERY_FS_INFO_ALLOCATION"
    _level_code = 0x0001
    fields_desc = [LEIntField("idFileSystem",0),
                   LEIntField("cSectorUnit",0),
                   LEIntField("cUnit",0),
                   LEIntField("cUnitAvailable",0),
                   LEShortField("cbSector",0)]

class SMB_QUERY_FS_INFO_VOLUME(_SMB_INFO,Packet):
    name="SMB Info (QUERY_FS) - SMB_QUERY_FS_INFO_VOLUME"
    _level_code = 0x0002
    fields_desc = [LEIntField("ulVolSerialNbr",0),
                   FieldLenField("cCharCount",None,length_of="VolumeLabel",fmt="B"),
                   SMB_UCHAR_LenField("VolumeLabel","",
                                      length_from=lambda pkt:pkt.cCharCount)]

class SMB_QUERY_FS_VOLUME_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY_FS) - SMB_QUERY_FS_VOLUME_INFO"
    _level_code = 0x0102
    fields_desc = [FILETIME_Field("VolumeCreationTime",None),
                   LEIntField("SerialNumber",0),
                   FieldLenField("VolumeLabelSize",None,length_of="VolumeLabel",fmt="<I"),
                   LEShortField("Reserved",0),
                   StrLenField("VolumeLabel","",codec="utf-16-le",
                               length_from=lambda pkt:pkt.VolumeLabelSize)]

class SMB_QUERY_FS_SIZE_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY_FS) - SMB_QUERY_FS_SIZE_INFO"
    _level_code = 0x0103
    fields_desc = [LESignedLongField("TotalAllocationUnits",0),
                   LESignedLongField("TotalFreeAllocationUnits",0),
                   LEIntField("SectorsPerAllocationUnit",0),
                   LEIntField("BytesPerSector",0)]

class SMB_QUERY_FS_DEVICE_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY_FS) - SMB_QUERY_FS_DEVICE_INFO"
    _level_code = 0x0104
    fields_desc = [LEIntEnumField("DeviceType",0,smb_enum_DeviceType),
                   LEFlagsField("DeviceCharacteristics",0,32,smb_flags_DeviceCharacteristics)]

class SMB_QUERY_FS_ATTRIBUTE_INFO(_SMB_INFO,Packet):
    name="SMB Info (QUERY_FS) - SMB_QUERY_FS_ATTRIBUTE_INFO"
    _level_code = 0x0105
    fields_desc = [LEFlagsField("FileSystemAttributes",0,32,smb_flags_FileSystemAttributes),
                   LEIntField("MaxFileNameLengthInBytes",0),
                   FieldLenField("LengthOfFileSystemName",None,length_of="FileSystemName",fmt="<I"),
                   StrLenField("FileSystemName","",codec="utf-16-le",
                               length_from=lambda pkt:pkt.LengthOfFileSystemName)]


################################################################################
##                                   BINDS                                    ##
################################################################################

def _set_andx_overloads():
    andx_req = []
    andx_res = []
    for g in globals().copy().itervalues():
        try:
            if issubclass(g, SMB_ANDX):
                if "_Req" in g.__name__:
                    andx_req.append(g)
                elif "_Res" in g.__name__:
                    andx_res.append(g)
        except:
            continue
    
    for g in globals().copy().itervalues():
        try:
            if not issubclass(g, SMB_COM):
                continue
            v = g.overload_fields[SMB_Header]["Command"]
        except:
            continue
        
        if "_Req" in g.__name__:
            a = andx_req
        elif "_Res" in g.__name__:
            a = andx_res
        else:
            continue
        
        for k in a:
            g.overload_fields[k] = {"AndXCommand":v}

_set_andx_overloads()


def _set_info_binds():
    for k,v in smb_info_set_codes.iteritems():
        i = globals().get("SMB_%s" % v, None)
        if i:
            bind_layers(SMB_TRANS2_SET_PATH_INFORMATION_Req, i, InformationLevel=k)
            bind_layers(SMB_TRANS2_SET_FILE_INFORMATION_Req, i, InformationLevel=k)

_set_info_binds()


bind_layers( NBTDatagram, SMB_Header, )
bind_layers( NBTSession, SMB_Header, )
