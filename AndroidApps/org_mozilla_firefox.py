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

class org_mozilla_firefox(IApp):
    name = "org.mozilla.firefox"
    cname = "Android mozillafirefox Browser"
    databases = { 
         "signons.sqlite": [ 
                KnownTable("moz_deleted_logins", None, 
                    {"timeDeleted":ConvertUtils.JsToUnix }, 
                    {"timeDeleted":DataTypes.DATE }),
                KnownTable("moz_logins", None, 
                    {"timeCreated":ConvertUtils.JsToUnix, 
		     "timeLastUsed":ConvertUtils.JsToUnix,
		     "timePasswordChanged":ConvertUtils.JsToUnix },
                    {"timeCreated": DataTypes.DATE, 
		     "timeLastUsed":DataTypes.DATE,
		     "timePasswordChanged":DataTypes.DATE }),
            ],
            "downloads.sqlite": [         
                KnownTable("moz_downloads", None, 
                    {"startTime":ConvertUtils.JsToUnix,"endTime":ConvertUtils.JsToUnix },
                    {"endTime":DataTypes.DATE, "endTime":DataTypes.DATE })
            ],
            "browser.db": [         
                KnownTable("bookmarks", None, 
                    {"created":ConvertUtils.JsToUnix, "modified":ConvertUtils.JsToUnix, "deleted":ConvertUtils.JsToUnix },
                    {"created":DataTypes.DATE, "modified":DataTypes.DATE, "deleted":DataTypes.DATE }),
		KnownTable("favicons", None, 
                    {"created":ConvertUtils.JsToUnix, "modified":ConvertUtils.JsToUnix },
                    {"created":DataTypes.DATE, "modified":DataTypes.DATE }),
		KnownTable("history", None, 
                    {"date":ConvertUtils.JsToUnix, "created":ConvertUtils.JsToUnix, "modified":ConvertUtils.JsToUnix,"deleted":ConvertUtils.JsToUnix },
                    {"date":DataTypes.DATE, "created":DataTypes.DATE, "modified":DataTypes.DATE, "deleted":DataTypes.DATE }),
		KnownTable("reading_list", None, 
                    {"read":ConvertUtils.JsToUnix, "deleted":ConvertUtils.JsToUnix, "modified":ConvertUtils.JsToUnix,"created":ConvertUtils.JsToUnix },
                    {"read":DataTypes.DATE, "deleted":DataTypes.DATE, "modified":DataTypes.DATE, "created":DataTypes.DATE })
            ],
            "health.db": [         
                KnownTable("android_metadata", None, 
                    {"platformVersion":ConvertUtils.JsToUnix, "platformBuildID":ConvertUtils.JsToUnix },
                    {"platformVersion":DataTypes.DATE, "platformBuildID":DataTypes.DATE }),
		KnownTable("environments", None, 
                    {"profileCreation":ConvertUtils.JsToUnix, "appBuildID":ConvertUtils.JsToUnix, "platformBuildID":ConvertUtils.JsToUnix },
                    {"profileCreation":DataTypes.DATE, "appBuildID":DataTypes.DATE, "platformBuildID":DataTypes.DATE }),
		KnownTable("events_integer", None, 
                    {"date":ConvertUtils.JsToUnix },
                    {"date":DataTypes.DATE  })
            ],
            "cookies.sqlite": [         
                KnownTable("moz_cookies", None, 
                    {"expiry":ConvertUtils.JsToUnix,"lastAccessed":ConvertUtils.JsToUnix, "creationTime":ConvertUtils.JsToUnix },
                    {"expiry":DataTypes.DATE, "lastAccessed":DataTypes.DATE,"creationTime":DataTypes.DATE })
            ],
	    "permissions.sqlite": [         
                KnownTable("moz_hosts", None, 
                    {"expireTime":ConvertUtils.JsToUnix },
                    {"expireTime":DataTypes.DATE })
            ],
  }

    def __init__(self):
        self.known = True
        
