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
from IMiscSource import IMiscSource,KnownFile,ParserType,FieldType,KnownFieldSQL
from IMiscSource import Label
from Catalog import Catalog

import re

class UserAccounts(IMiscSource):
    version = [18,19,20,21]
    catalog_id = Catalog.CATALOG_DEVINFO
    title = Label( "Accounts", "accounts" )
    relative_directories = [ "system", "users", re.compile("^\d+$") ]
    knownfiles = {
        "accounts.db": KnownFile(ParserType.TYPE_SQLITE3,
            {
                Label("Accounts", "accounts") : [
                    KnownFieldSQL( 
                        FieldType.TYPE_ARRAY,
                        """
                        SELECT *
                        FROM accounts
                        """,
                        contents= [
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                           "Account ID", "_id" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Name", 
                                           "name" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, "Type", 
                                           "type" ),
                            KnownFieldSQL( FieldType.TYPE_STR, None, 
                                           "Password (Hash)", "password" ),
                        ]
                    ),
                ],
            }
        )
    }
