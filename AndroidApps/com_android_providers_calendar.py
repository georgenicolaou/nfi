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
from IApp import IApp, KnownTable, DataTypes
import ConvertUtils

class com_android_providers_calendar(IApp):
    name = "com.android.providers.calendar"
    cname = "Calendar Provider"
    databases = {
        "calendar.db": [
            KnownTable("_sync_state", None, 
               None, 
               {"data": DataTypes.DATA}),
            KnownTable("Events", None, 
               {"dtend": ConvertUtils.JsToUnix, 
                "lastDate": ConvertUtils.JsToUnix,
                "dtstart": ConvertUtils.JsToUnix}, 
               {"dtend": DataTypes.DATE, 
                "lastDate": DataTypes.DATE,
                "dtstart": DataTypes.DATE}),
            KnownTable("Instances", None,
                {"begin": ConvertUtils.JsToUnix, "end": ConvertUtils.JsToUnix},
                {"begin": DataTypes.DATE, "end": DataTypes.DATE}),
            KnownTable("view_events", None,
                {"lastDate": ConvertUtils.JsToUnix,
                 "dtend": ConvertUtils.JsToUnix,
                 "dtstart": ConvertUtils.JsToUnix,
                 "dtend": ConvertUtils.JsToUnix},
                {"lastDate": DataTypes.DATE,
                 "dtend": DataTypes.DATE,
                 "dtstart": DataTypes.DATE,
                 "dtend": DataTypes.DATE})
        ]
    }

    def __init__(self):
        self.known = True
        
