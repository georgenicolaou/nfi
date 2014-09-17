'''
NFI -- Silensec's Nyuki Forensics Investigator

Copyright (C) 2014  George Nicolaou (george[at]silensec[dot]com)
                    Silensec Ltd.
                    Juma Fredrick (j.fredrick[at]silensec[dot]com)
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
from IApp import IApp, KnownTable, DataTypes
import ConvertUtils

class com_android_vending(IApp):
    name = "com.android.vending"
    cname = "Android Vending"
    databases = {
        "suggestions.db": [
            KnownTable("suggestions", None,
                {"date":ConvertUtils.JsToUnix  },
                {"date":DataTypes.DATE  })
        ],
        "localappstate.db": [
            KnownTable("appstate", None,
                {"first_download_ms":ConvertUtils.JsToUnix,
                 "delivery_data_timestamp_ms":ConvertUtils.JsToUnix,
                 "last_update_timestamp_ms":ConvertUtils.JsToUnix },
                {"first_download_ms":DataTypes.DATE,
                 "delivery_data_timestamp_ms":DataTypes.DATE,
                 "last_update_timestamp_ms":DataTypes.DATE }),
        ],
        "package_verification.db": [
            KnownTable("verification_cache", None,
                {"cache_fingerprint":ConvertUtils.JsToUnix },
                {"cache_fingerprint":DataTypes.DATE })
            ],
  }

    def __init__(self):
        self.known = True
        
