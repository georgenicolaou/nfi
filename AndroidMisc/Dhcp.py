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

class Dhcp(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_NETWORKING
    title = Label( "DHCP Information", "dhcp_info" )
    relative_directories = [ "misc", "dhcp" ]
    knownfiles = {
        "dnsmasq.leases": KnownFile(ParserType.TYPE_REGEX,
            {
                Label("Dnsmasq Leases", "dnsmasq_leases"): [
                    KnownField( FieldType.TYPE_CONTAINER, "(.*)\n", "leases",
                        contents=[
                            KnownField( FieldType.TYPE_DATE, "^(\d+)", 
                                        "expiry_date" 
                                        "Expiry Date" ),
                            KnownField( FieldType.TYPE_STR, "^\d+ ([\w:]+)", 
                                        "ap_mac",
                                        "Client MAC Address" ),
                            KnownField( FieldType.TYPE_STR, 
                                        "^\d+ [\w:]+ ([\d\.]+)",
                                        "leased_ip" ,
                                        "Leased IP Address" ),
                            KnownField( FieldType.TYPE_STR, 
                                        "^\d+ [\w:]+ [\d\.]+ (.*?) ",
                                        "hostname", 
                                        "Hostname" ),
                        ]
                    )
                ]
            }
        ),
    }
