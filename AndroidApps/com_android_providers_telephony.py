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

class com_android_providers_telephony(IApp):
    name = "com.android.providers.telephony"
    cname = "Android Providers Telephony"
    databases = {
        "mmssms.db": [
            KnownTable("pdu", None, 
                {"date":ConvertUtils.UnixTimestamp, 
                 "date_sent":ConvertUtils.UnixTimestamp }, 
                {"date":DataTypes.DATE, "date_sent":DataTypes.DATE }),
            KnownTable("pending_msgs", None,
                {"due_time":ConvertUtils.UnixTimestamp,
                 "last_try":ConvertUtils.UnixTimestamp },
                {"due_time": DataTypes.DATE,
                 "last_try":DataTypes.DATE }),
            KnownTable("rate", None,
                {"sent_time":ConvertUtils.UnixTimestamp },
                {"sent_time": DataTypes.DATE }),
            KnownTable("raw", None,
                {"date":ConvertUtils.UnixTimestamp },
                {"date": DataTypes.DATE }),
            KnownTable("sms", None,
                {"date":ConvertUtils.JsToUnix, 
                 "date_sent":ConvertUtils.JsToUnix },
                {"date": DataTypes.DATE,"date_sent":DataTypes.DATE }),
            KnownTable("threads", None, 
                    {"date":ConvertUtils.JsToUnix },
                    {"date": DataTypes.DATE })
        ],
  }

    def __init__(self):
        self.known = True
        
