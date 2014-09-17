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

class com_android_providers_media(IApp):
    name = "com.android.providers.media"
    cname = "Android Providers Media"
    databases = {
        "external.db": [
            KnownTable("files", None,
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp,
                 "datetaken":ConvertUtils.JsToUnix,
                 "duration":ConvertUtils.UnixTimestamp },
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE ,
                 "datetaken":DataTypes.DATE,
                 "duration":DataTypes.DATE }),
            KnownTable("searchhelpertitle", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE}),
            KnownTable("audio_meta", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE}),
            KnownTable("audio", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE}),
            KnownTable("images", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp,
                 "datetaken":ConvertUtils.JsToUnix},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE,
                 "datetaken":DataTypes.DATE}),
            KnownTable("video", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp,
                 "datetaken":ConvertUtils.JsToUnix},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE,
                 "datetaken":DataTypes.DATE}),
            #KnownTable("log", None, #XXX need to fix this somehow
            #   {"time":ConvertUtils.UnixTimestamp },
            #   {"time": DataTypes.DATE })
        ],
	    "internal.db": [
            KnownTable("searchhelpertitle", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE}),
            KnownTable("audio_meta", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE}),
            KnownTable("audio", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE}),
            KnownTable("images", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp,
                 "datetaken":ConvertUtils.JsToUnix},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE,
                 "datetaken":DataTypes.DATE}),
            KnownTable("video", None, 
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp,
                 "datetaken":ConvertUtils.JsToUnix},
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE,
                 "datetaken":DataTypes.DATE}),
            KnownTable("files", None,
                {"date_added":ConvertUtils.UnixTimestamp,
                 "date_modified":ConvertUtils.UnixTimestamp,
                 "datetaken":ConvertUtils.JsToUnix,
                 "duration":ConvertUtils.UnixTimestamp },
                {"date_added":DataTypes.DATE,
                 "date_modified":DataTypes.DATE ,
                 "datetaken":DataTypes.DATE,
                 "duration":DataTypes.DATE }),
	    ],
  }

    def __init__(self):
        self.known = True
        
