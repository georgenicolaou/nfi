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
import re

class com_google_android_gm(IApp):
    name = "com.google.android.gm"
    cname = "Google Gmail"
    databases = { 
         re.compile("mailstore\.[^@]+@[^@]+\.[^@]+\.db"): [ 
                KnownTable("conversation_labels", None, 
                    {"date":ConvertUtils.JsToUnix,},
                    {"date":DataTypes.DATE,}),
        		KnownTable("conversations_to_fetch", None, 
                    {"nextAttemptDateM":ConvertUtils.JsToUnix  },
                    {"nextAttemptDateM":DataTypes.DATE }),
        		KnownTable("labels", None, 
                    {"lastTouched":ConvertUtils.JsToUnix, 
                     "lastMessageTimestamp":ConvertUtils.JsToUnix  },
                    {"lastTouched":DataTypes.DATE, 
                     "lastMessageTimestamp":DataTypes.DATE }),
        		KnownTable("messages", None, 
                    {"dateSentMs":ConvertUtils.JsToUnix, 
                     "dateReceivedMs":ConvertUtils.JsToUnix },
                    {"dateSentMs":DataTypes.DATE, 
                     "dateReceivedMs":DataTypes.DATE }),
        		KnownTable("operations", None, 
                    {"nextTimeToAttempt":ConvertUtils.JsToUnix  },
                    {"nextTimeToAttempt":DataTypes.DATE }),
            ],
            "webview.db": [
                KnownTable("formdata", 
                    """
                    SELECT 
                        formdata._id, 
                        urlid, 
                        formurl.url, 
                        value 
                    FROM formdata 
                    INNER JOIN formurl on formdata.urlid = formurl._id""")
            ],
            "webviewCookiesChromium.db": [         
                KnownTable("cookies", None, 
                    {"creation_utc":ConvertUtils.WebkitToUnix,
                     "expires_utc":ConvertUtils.WebkitToUnix,
                     "last_access_utc":ConvertUtils.WebkitToUnix},
                    {"creation_utc":DataTypes.DATE, 
                     "expires_utc":DataTypes.DATE, 
                     "last_access_utc":DataTypes.DATE})
            ],
  }

    def __init__(self):
        self.known = True
        
