'''
NFI -- Silensec's Nyuki Forensics Investigator

Copyright (C) 2014  George Nicolaou (george[at]silensec[dot]com)
                    Silensec Ltd.

This file is part of Nyuki Forensics Investigator (NFI).

NFI is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

NFI is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NFI.  If not, see <http://www.gnu.org/licenses/>.
'''
from IMiscSource import IMiscSource,KnownFile,ParserType,FieldType,KnownField
from IMiscSource import Label
from Catalog import Catalog

class SELinuxLog(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_LOGS
    title = Label( "SELinux Audit Log", "selinux" )
    relative_directories = [ "misc", "audit" ]
    
    knownfiles = {
        "audit.log": KnownFile(ParserType.TYPE_REGEX,
            {
                Label("File System Logs", "filesyste_logs"): [
                    KnownField( FieldType.TYPE_CONTAINER, 
                                "(.*?tclass=(dir|file|ipc|fifo_file|chr_file|" +
                                "filesystem|lnk_file|association|fd|" +
                                "sock_file|unix_stream_socket|netlink_nflog_socket))\n",
                                "logs_container",
                        contents=[
                            KnownField( FieldType.TYPE_DATE, "msg=audit\((\d*)", 
                                        "date", "Date" ),
                            KnownField( FieldType.TYPE_STR, "avc:\s+?(\w+)", 
                                        "action", "Action" ),
                            KnownField( FieldType.TYPE_STR, "\{\s+?(\w+)\s+}", 
                                        "permission", "Permission" ),
                            KnownField( FieldType.TYPE_STR, "pid=(\d+)", 
                                        "pid", "PID" ),
                            KnownField( FieldType.TYPE_STR, "comm=\"(.*?)\"", 
                                        "command", "Command" ),
                            KnownField( FieldType.TYPE_STR, "name=\"(.*?)\"|group=\"(.*?)\"", 
                                        "name", "Name/Path" ),
                            KnownField( FieldType.TYPE_STR, "dev=(\w+)\s", 
                                        "dev", "Device"),
                            KnownField( FieldType.TYPE_STR, "ino=(\d+)\s", 
                                        "inode", "inode"),
                            KnownField( FieldType.TYPE_STR, "scontext=(.*?)\s", 
                                        "source_context", "Source Context"),
                            KnownField( FieldType.TYPE_STR, "tcontext=(.*?)\s",
                                        "target_context", "Target Context"),
                            KnownField( FieldType.TYPE_STR, "tclass=(.*)", 
                                        "target_class", "Target Class")
                        ]
                    )
                ],
                
                Label("Networking", "networking_logs"): [
                    KnownField( FieldType.TYPE_CONTAINER, 
                        "(.*?tclass=(key_socket|netif|netlink_socket|" +
                        "netlink_audit_socket|netlink_ip6fw_socket|" +
                        "netlink_kobject_uevent_socket|" +
                        "netlink_route_socket|" +
                        "netlink_selinux_socket|" +
                        "netlink_tcpdiag_socket|netlink_xfrm_socket|" +
                        "node|packet|packet_socket|peer|rawip_socket|" +
                        "socket|tcp_socket|tun_socket|udp_socket|" +
                        "unix_dgram_socket))\n",
                        "logs_container",
                        contents= [
                            KnownField( FieldType.TYPE_DATE, "msg=audit\((\d*)", 
                                        "date", "Date" ),
                            KnownField( FieldType.TYPE_STR, "avc:\s+?(\w+)", 
                                        "action", "Action" ),
                            KnownField( FieldType.TYPE_STR, "\{\s+?(\w+)\s+}", 
                                        "permission", "Permission" ),
                            KnownField( FieldType.TYPE_STR, "pid=(\d+)", 
                                        "pid", "PID" ),
                            KnownField( FieldType.TYPE_STR, "comm=\"(.*?)\"", 
                                        "command", "Command" ),
                            KnownField( FieldType.TYPE_STR, "src=(\d+)|lport=(\d+)", 
                                        "source", "Source/Bind Port" ),
                            KnownField( FieldType.TYPE_STR, "dest=(\d+)", 
                                        "dest", "Destination" ),
                            KnownField( FieldType.TYPE_STR, "scontext=(.*?)\s", 
                                        "source_context", "Source Context"),
                            KnownField( FieldType.TYPE_STR, "tcontext=(.*?)\s",
                                        "target_context", "Target Context"),
                            KnownField( FieldType.TYPE_STR, "tclass=(.*)", 
                                        "target_class", "Target Class")
                        ]
                    )
                ],
            }
        ),
    }

"""
"System": [ #XXX fill this
                    KnownField( FieldType.TYPE_CONTAINER, "(.*?tclass=(security|"+
                                "system|dbus|context|nscd|passwd|capability|capability2))\n"  )
                ],
             "Process Control Logs": [ #XXX TODO
                    KnownField( FieldType.TYPE_CONTAINER, 
                        "(.*?tclass=(kernel_service|key|memprotect|" +
                        "msg|msgq|process|sem|shm))\n", 
                    )
                ]
"""