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

class com_viber_voip(IApp):
    name = "com.viber.voip"
    cname = "Android Viber Voip"
    databases = {
        "webviewCookiesChromium.db": [
            KnownTable("cookies", None,
                {"creation_utc":ConvertUtils.WebkitToUnix, 
                 "expires_utc":ConvertUtils.WebkitToUnix, 
                 "last_access_utc":ConvertUtils.WebkitToUnix },
                {"creation_utc":DataTypes.DATE, 
                 "expires_utc":DataTypes.DATE, 
                 "last_access_utc":DataTypes.DATE })
        ],
	    "viber_messages": [
            KnownTable("conversations", None,
                {"smart_event_date":ConvertUtils.JsToUnix, 
                 "date":ConvertUtils.JsToUnix },
                {"smart_event_date":DataTypes.DATE, 
                 "date":DataTypes.DATE }),
            KnownTable("messages", None,
                {"date":ConvertUtils.JsToUnix, 
                 "date_real":ConvertUtils.JsToUnix },
                {"date":DataTypes.DATE, "date_real":DataTypes.DATE }),
            KnownTable("messages_calls", None,
                {"date":ConvertUtils.JsToUnix },
                {"date":DataTypes.DATE }),
            KnownTable("purchase", None,
                {"purchase_time":ConvertUtils.JsToUnix },
                {"purchase_time":DataTypes.DATE })
        ],
	    "viber_data": [
            KnownTable("blockednumbers", None,
                {"blocked_date":ConvertUtils.JsToUnix },
                {"blocked_date":DataTypes.DATE }),
            KnownTable("calls", None,
                {"date":ConvertUtils.JsToUnix },
                {"date":DataTypes.DATE, }),
            KnownTable("phonebookcontact", None,
                {"recently_joined_date":ConvertUtils.JsToUnix, 
                 "joined_date":ConvertUtils.JsToUnix },
                {"recently_joined_date":DataTypes.DATE, 
                 "joined_date":DataTypes.DATE })
        ],
  }

    def __init__(self):
        self.known = True
        
