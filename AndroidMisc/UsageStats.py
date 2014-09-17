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
import ConvertUtils

class UsageStats(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_LOGS
    title = Label( "Usage Stats", "usage_stats" )
    relative_directories = [ "system", "usagestats" ]
    knownfiles = {
        "usage-history.xml": KnownFile(ParserType.TYPE_XML,
            {
                Label("Usage Stats", "usage_stats") : [ 
                    KnownFieldXML( 
                        FieldType.TYPE_ARRAY, 
                        "./pkg/comp", 
                        "usage_stats",
                        contents = [
                            KnownFieldXML( 
                                FieldType.TYPE_STR,
                                ".",
                                "activity_name",
                                "Activity",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "name"
                            ),
                            KnownFieldXML(
                                FieldType.TYPE_DATE,
                                ".",
                                "last_run",
                                "Last Run Time",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "lrt",
                                converter = ConvertUtils.JsToUnix
                            )
                        ]
                    )
                ]
            }
        )
    }