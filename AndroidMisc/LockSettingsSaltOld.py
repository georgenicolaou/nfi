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
from IMiscSource import IMiscSource, KnownFile, ParserType, KnownFieldSQL, FieldType
from IMiscSource import KnownField, KnownFieldBin, BinaryClass, BinaryRead
from IMiscSource import KnownFieldXML, ReadTypeXML, Label
from Catalog import Catalog
import ConvertUtils

PASSWORD_QUALITY = {
    0: "PASSWORD_QUALITY_UNSPECIFIED",
    0x8000: "PASSWORD_QUALITY_BIOMETRIC_WEAK",
    0x10000: "PASSWORD_QUALITY_SOMETHING",
    0x20000: "PASSWORD_QUALITY_NUMERIC",
    0x40000: "PASSWORD_QUALITY_ALPHABETIC",
    0x50000: "PASSWORD_QUALITY_ALPHANUMERIC",
    0x60000: "PASSWORD_QUALITY_COMPLEX"
}
def password_type_tostr(val):
    try:
        val = int(val)
        if val in PASSWORD_QUALITY:
            return PASSWORD_QUALITY[val]
    except:
        pass
    return "Unknown"

class LockSettings(IMiscSource):
    version = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]
    catalog_id = Catalog.CATALOG_DEVINFO
    title = Label( "Screen Lock", "screen_lock" )
    relative_directories = [ "data", "com.android.providers.settings", 
                            "databases" ]
    
    knownfiles = {
        "settings.db": KnownFile(ParserType.TYPE_SQLITE3,
            {
                Label("Lock Settings", "lock_settings"): [
                    KnownFieldSQL( FieldType.TYPE_STR, 
                        """
                        SELECT value FROM 
                        secure 
                        WHERE name = 'lock_screen_owner_info'
                        """,
                        "Owner Info",
                        "lock_screen_owner_info",
                    ),
                    KnownFieldSQL( FieldType.TYPE_STR, 
                        """
                        SELECT value FROM 
                        secure 
                        WHERE name = 'lockscreen.password_salt'
                        """,
                        "Password Salt",
                        "password_salt",
                    ),
                    KnownFieldSQL( FieldType.TYPE_STR, 
                        """
                        SELECT value FROM 
                        locksettings 
                        WHERE name = 'lockscreen.password_type'
                        """,
                        "Password Quality",
                        "lockscreen.password_type",
                        converter=password_type_tostr
                    ),
                ]
            }
        )
    }