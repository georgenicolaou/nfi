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

class com_facebook_orca(IApp):
    name = "com.facebook.orca"
    cname = "Android Facebook Orca"
    databases = {
        "newsfeed_db": [
            KnownTable("home_stories", None, 
                {"fetched_at":ConvertUtils.JsToUnix}, 
                {"fetched_at":DataTypes.DATE}),
            KnownTable("feed_unit_impression", None,
                {"timestamp":ConvertUtils.JsToUnix},
                {"timestamp":DataTypes.DATE}),
        ],
        "offline_mode_db":[
            KnownTable("pending_request", None,
                {"created_time" :ConvertUtils.JsToUnix,
                 "expire_duration_ms":ConvertUtils.JsToUnix},
                {"created_time" :DataTypes.DATE,
                 "expire_duration_ms":DataTypes.DATE}
            )
        ],
        "contacts_db2": [
            KnownTable("contacts", None, 
                {"added_time_ms":ConvertUtils.JsToUnix}, 
                {"added_time_ms":DataTypes.DATE}),
            KnownTable("contact_summaries", None,
                {"added_time_ms":ConvertUtils.JsToUnix}, 
                {"added_time_ms":DataTypes.DATE}),
        ],
        "videocache_db": [
            KnownTable("videoads", None,
                {"time_start":ConvertUtils.JsToUnix,
                 "time_end":ConvertUtils.JsToUnix,
                 "fetch_time":ConvertUtils.JsToUnix},
                {"time_start":DataTypes.DATE,
                 "time_end":DataTypes.DATE,
                 "fetch_time":DataTypes.DATE})
        ],
        "threads_db2": [
            KnownTable("folder_counts", None,
                {"last_seen_time":ConvertUtils.JsToUnix},
                {"last_seen_time":DataTypes.DATE}),
            KnownTable("folders", None,
                {"timestamp_ms":ConvertUtils.JsToUnix},
                {"timestamp_ms":DataTypes.DATE}),
            KnownTable("threads", None,
                {"timestamp_ms":ConvertUtils.JsToUnix,
                 "last_fetch_time_ms":ConvertUtils.JsToUnix},
                {"timestamp_ms":DataTypes.DATE,
                 "last_fetch_time_ms":DataTypes.DATE}),
            KnownTable("messages", None,
                {"timestamp_ms":ConvertUtils.JsToUnix,
                 "timestamp_send_ms":ConvertUtils.JsToUnix},
                {"timestamp_ms":DataTypes.DATE,
                 "timestamp_send_ms":DataTypes.DATE}),
        ],
        "analytics_db2":[
            KnownTable("events", None,
                {"timestamp":ConvertUtils.JsToUnix},
                {"timestamp":DataTypes.DATE})
        ],
        "mds_cache_db":[
            KnownTable("cache", None,
                {"timestamp":ConvertUtils.JsToUnix},
                {"timestamp":DataTypes.DATE})
        ],
        "timeline_prefetch_db":[
            KnownTable("prefetch_candidates", None,
                {"last_generate_timestamp":ConvertUtils.JsToUnix,
                 "last_fetch_timestamp":ConvertUtils.JsToUnix},
                {"last_generate_timestamp":DataTypes.DATE,
                 "last_fetch_timestamp":DataTypes.DATE})
        ],
        "timeline_db":[
            KnownTable("cache", None,
                {"timestamp":ConvertUtils.JsToUnix},
                {"timestamp":DataTypes.DATE})
        ],
        "graphql_cache":[
            KnownTable("queries", None,
                {"timestamp":ConvertUtils.JsToUnix},
                {"timestamp":DataTypes.DATE})
        ],
        "sticker_packs":[
            KnownTable("sticker_packs", None,
                {"updated_time":ConvertUtils.UnixTimestamp},
                {"updated_time":DataTypes.DATE})
        ],
        "webviewCookiesChromium.db": [
            KnownTable("cookies", None,
                {"creation_utc":ConvertUtils.WebkitToUnix,
                 "expires_utc":ConvertUtils.WebkitToUnix,
                 "last_access_utc":ConvertUtils.WebkitToUnix },
                {"creation_utc":DataTypes.DATE,
                 "expires_utc":DataTypes.DATE,
                 "last_access_utc":DataTypes.DATE })
        ],
        "webviewCookiesChromiumPrivate.db": [
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
        
