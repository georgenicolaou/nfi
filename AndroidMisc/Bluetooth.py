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
from IMiscSource import IMiscSource,KnownFile,ParserType,FieldType,KnownField,KnownFieldXML,ReadTypeXML
from IMiscSource import Label
from Catalog import Catalog

class Bluetooth(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_NETWORKING
    title = Label( "Bluetooth Information", "bluetooth_info" )
    relative_directories = [ "misc", "bluedroid" ]
    knownfiles = {
        "bt_config.xml": KnownFile(ParserType.TYPE_XML,
            {
                Label("Device Info", "device_info") : [
                    KnownFieldXML( 
                        FieldType.TYPE_STR, 
                        "*[@Tag='Local']/*[@Tag='Adapter']/*[@Tag='Address']",
                        "device_hardware_address", 
                        "Device Hardware Address"
                    ),
                ],
                Label("Paired Devices", "paired_devices") : [
                    KnownFieldXML(
                        FieldType.TYPE_CONTAINER,
                        "*[@Tag='Remote']",
                        "paired_devices",
                        contents = [
                            KnownFieldXML( 
                                FieldType.TYPE_STR,
                                ".",
                                "device_hardware_address",
                                "Device Hardware Address",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "Tag" ),
                            KnownFieldXML( 
                                FieldType.TYPE_DATE, 
                                "./*[@Tag='Timestamp']",
                                "pair_date",
                                "Pair Date" ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                "./*[@Tag='Name']",
                                "device_name", 
                                "Device Name" )
                        ]
                    )
                ]
            }
        )
    }