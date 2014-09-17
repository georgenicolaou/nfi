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

class com_google_android_gallery3d(IApp):
    name = "com.google.android.gallery3d"
    cname = "Google android Gallery3d"
    databases = {
        "picasa.db": [
            KnownTable("albums", None,
                {"date_updated":ConvertUtils.JsToUnix, 
                 "date_published":ConvertUtils.JsToUnix,
                 "date_edited":ConvertUtils.JsToUnix },
                {"date_updated":DataTypes.DATE,
                 "date_published":DataTypes.DATE,
                 "date_edited":DataTypes.DATE }),
            KnownTable("photos", None,
                {"date_edited":ConvertUtils.JsToUnix,
                 "date_updated":ConvertUtils.JsToUnix,
                 "date_taken":ConvertUtils.JsToUnix,
                 "date_published":ConvertUtils.JsToUnix },
                {"date_edited": DataTypes.DATE,
                 "date_updated":DataTypes.DATE,
                 "date_taken":DataTypes.DATE,
                 "date_published":DataTypes.DATE }),
        ],
        "picasa.upload.db": [
            KnownTable("upload_records", None,
                {"uploaded_time":ConvertUtils.JsToUnix, 
                 "timestamp":ConvertUtils.UnixTimestamp },
                {"uploaded_time":DataTypes.DATE, 
                 "timestamp":DataTypes.DATE }),
            KnownTable("upload_tasks", None,
                {"uploaded_time":ConvertUtils.JsToUnix},
                {"uploaded_time":DataTypes.DATE})
        ],
  }

    def __init__(self):
        self.known = True
        
