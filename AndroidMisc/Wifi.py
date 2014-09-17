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
from IMiscSource import KnownFieldBin, Endianess, BinaryClass, BinaryRead
from IMiscSource import Label
from Catalog import Catalog

import re

class WiFi(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_NETWORKING
    title = Label( "Wifi Information", "wifi_info" )
    relative_directories = [ "misc", "wifi" ]
    knownfiles = {
        "wpa_supplicant.conf": KnownFile(ParserType.TYPE_REGEX,
            {
                Label("Device Info", "device_info") : [ 
                    KnownField( 
                        FieldType.TYPE_STR, 
                        "ctrl_interface=(.*?)\n", 
                        "interface",
                        "Wifi Interface" 
                    ),
                    KnownField( 
                        FieldType.TYPE_STR, 
                        "device_name=(.*?)\n",
                        "dev_name" 
                        "Device Name" 
                    ),
                    KnownField( 
                        FieldType.TYPE_STR, 
                        "manufacturer=(.*?)\n", 
                        "manufacturer",
                        "Manufacturer" 
                    )
                ],
                Label("Connected Networks", "connected_networks"): [
                    KnownField( FieldType.TYPE_CONTAINER, 
                                "network=\{[\s\S.]*?\}", "connected_networks",
                                "networks_container", 
                        contents=[
                            KnownField( FieldType.TYPE_STR, "ssid=(.*?)\n", 
                                        "ssid", "Network SSID" ),
                            KnownField( FieldType.TYPE_STR, "bssid=(.*?)\n", 
                                        "ap_address", "AP Address" ),
                            KnownField( FieldType.TYPE_STR, "key_mgmt=(.*?)\n", 
                                        "security", "Security" ),
                            KnownField( FieldType.TYPE_STR, "psk=(.*?)\n", 
                                        "password", "Password" ),
                            KnownField( FieldType.TYPE_STR, "priority=(.*?)\n", 
                                        "priority", "Network Priority" )
                        ]
                    )
                ]
            }
        ),
        "hostapd.conf": KnownFile(ParserType.TYPE_REGEX,
            {
                Label("Wifi Tethering", "wifi_tethering"): [
                    KnownField( FieldType.TYPE_STR, "interface=(.*?)\n", 
                                "tethering_interface", "Tethering Interface" ),
                    KnownField( FieldType.TYPE_STR, "ssid=(.*?)\n", 
                                "network_name", "Network Name" ),
                    KnownField( FieldType.TYPE_STR, "channel=(.*?)\n", 
                                "channel", "Channel" ),
                    KnownField( FieldType.TYPE_STR, "wpa_psk=(.*?)\n", 
                                "wpa_passkey", "WPA Passkey" )
                ]
            }
        ),
        "softap.conf": KnownFile( ParserType.TYPE_BINARY,
            {
                Label("Wifi Tethering", "wifi_tethering"): [
                    KnownFieldBin( BinaryClass.ENUMERATION, BinaryRead.INTEGER, 
                                   "file_version", "File Version", 
                                   { 1: "VERSION 1"} ),
                    KnownFieldBin( BinaryClass.CONSUME, BinaryRead.SHORT, 
                                   "ssidlength", None ),
                    KnownFieldBin( BinaryClass.UTF8, "ssidlength", "ap_name", 
                                   "AP Network Name (Software)" ),
                    KnownFieldBin( BinaryClass.ENUMERATION, BinaryRead.INTEGER,
                                    "auth_type", "Security", 
                                    { 0: "NONE", 1: "WPA_PSK", 2: "WPA_EAP", 
                                     3: "IEEE8021X", 4: "WPA2_PSK"} ),
                    KnownFieldBin( BinaryClass.CONSUME, BinaryRead.SHORT, 
                                   "passlength", None ),
                    KnownFieldBin( BinaryClass.UTF8, "passlength", "pass", 
                                   "Password (Plain)" )
                ]
            }
        )
    }
