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

class com_google_android_feedback(IApp):
    name = "com.google.android.feedback"
    cname = "Google Android Feedback"
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
  }

    def __init__(self):
        self.known = True
        
