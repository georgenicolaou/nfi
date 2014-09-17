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
import ConvertUtils, re

class com_twitter_android(IApp):
    name = "com.twitter.android"
    cname = "Android Twitter"
    databases = {
        re.compile("\d+-\d+\.db") : [
            KnownTable("active_tailfeather", None,
                {"start_time":ConvertUtils.JsToUnix,
                 "end_time":ConvertUtils.JsToUnix},
                {"start_time":DataTypes.DATE,
                 "end_time":DataTypes.DATE}),   
            KnownTable("activities",None,
                {"created_at":ConvertUtils.JsToUnix},
                {"created_at":DataTypes.DATE}
            ),
    		KnownTable("clusters",None,
                {"cl_timestamp":ConvertUtils.JsToUnix},
                {"cl_timestamp":DataTypes.DATE}),
    		KnownTable("conversation_entries", None,
                {"created":ConvertUtils.JsToUnix},
                {"created":DataTypes.DATE}),
            KnownTable("conversation_participants",None,
                {"join_time":ConvertUtils.JsToUnix},
                {"join_time":DataTypes.DATE}),
    		KnownTable("message_drafts",None,
                {"created":ConvertUtils.JsToUnix},
                {"created":DataTypes.DATE}),
    		KnownTable("messages",None,
                {"created":ConvertUtils.JsToUnix},
                {"created":DataTypes.DATE}),
    		KnownTable("peeks",None,
                {"timestamp":ConvertUtils.JsToUnix},
                {"timestamp":DataTypes.DATE}),
    		KnownTable("places",None,
                {"updated_at":ConvertUtils.JsToUnix},
                {"updated_at":DataTypes.DATE}),
    		KnownTable("search_queries",None,
                {"time":ConvertUtils.JsToUnix},
                {"time":DataTypes.DATE}),
    		KnownTable("status_groups", None,
                {"updated_at":ConvertUtils.JsToUnix},
                {"updated_at":DataTypes.DATE}),
            KnownTable("statuses",None,
                {"created":ConvertUtils.JsToUnix},
                {"created":DataTypes.DATE}),
    		KnownTable("timeline",None,
                {"updated_at":ConvertUtils.JsToUnix},
                {"updated_at":DataTypes.DATE}),
            KnownTable("topics",None,
                {"ev_start_time":ConvertUtils.JsToUnix},
                {"ev_start_time":DataTypes.DATE}),
    		KnownTable("users",None,
                {"profile_created":ConvertUtils.JsToUnix,
                 "updated":ConvertUtils.JsToUnix},
                {"profile_created":DataTypes.DATE,
                 "updated":DataTypes.DATE})
		],
		
		"webviewCookiesChromium.db": [
            KnownTable("cookies",None,
                {"creation_utc":ConvertUtils.WebkitToUnix,
                 "expires_utc":ConvertUtils.WebkitToUnix, 
                 "last_access_utc":ConvertUtils.WebkitToUnix},
                {"creation_utc":DataTypes.DATE, 
                 "expires_utc":DataTypes.DATE, 
                 "last_access_utc":DataTypes.DATE})
        ],
        
        re.compile("\d+-drafts.db"): [
            KnownTable("drafts",None,
                {"updated_at":ConvertUtils.JsToUnix},
                {"updated_at":DataTypes.DATE})
		],
                  
		"webviewCookiesChromiumPrivate.db": [
            KnownTable("cookies",None,
                {"creation_utc":ConvertUtils.WebkitToUnix, 
                 "expires_utc":ConvertUtils.WebkitToUnix, 
                 "last_access_utc":ConvertUtils.WebkitToUnix},
                {"creation_utc":DataTypes.DATE, 
                 "expires_utc":DataTypes.DATE, 
                 "last_access_utc":DataTypes.DATE}),
		],
    }

    def __init__(self):
        self.known = True
        
