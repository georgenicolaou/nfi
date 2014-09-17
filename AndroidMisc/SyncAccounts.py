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

class SyncAccounts(IMiscSource):
    version = []
    catalog_id = Catalog.CATALOG_DEVINFO
    title = Label( "Accounts", "accounts" )
    relative_directories = [ "system", "sync" ]
    knownfiles = {
        "accounts.xml": KnownFile(ParserType.TYPE_XML,
            {
                Label("Sync Accounts", "sync_accounts") : [ 
                    KnownFieldXML( 
                        FieldType.TYPE_ARRAY, 
                        "./authority", 
                        "sync_accounts",
                        contents = [
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "account_id",
                                "Id",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "id" 
                            ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "account_name",
                                "Account",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "account" 
                            ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "owning_user",
                                "Owning User",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "user" 
                            ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "account_type"
                                "Account Type",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "type" 
                            ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "authority",
                                "Authority",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "authority" 
                            ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "enabled",
                                "Enabled",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "enabled" 
                            ),
                            KnownFieldXML( 
                                FieldType.TYPE_STR, 
                                ".", 
                                "sync_enabled",
                                "Sync Enabled",
                                read_type = ReadTypeXML.READ_ATTR,
                                attr = "syncable" 
                            ),
                        ]
                    )
                ]
            }
        )
    }