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

class com_android_chrome(IApp):
    name = "com.android.chrome"
    cname = "Android Chrome Browser"
    databases = {
        "History": [ 
            KnownTable("downloads", None, 
                {"start_time":ConvertUtils.WebkitToUnix, 
                 "end_time":ConvertUtils.WebkitToUnix}, 
                {"start_time":DataTypes.DATE, "end_time":DataTypes.DATE}),
            KnownTable("segment_usage", None, 
                {"time_slot":ConvertUtils.WebkitToUnix},
                {"time_slot":DataTypes.DATE}),
            KnownTable("urls", None,
                {"last_visit_time":ConvertUtils.WebkitToUnix},
                {"last_visit_time": DataTypes.DATE}),
            KnownTable("visits", None,
                {"visit_time":ConvertUtils.WebkitToUnix },
                {"visit_time":DataTypes.DATE })
        ],
        "Cookies": [
            KnownTable("cookies", None,
                {"creation_utc":ConvertUtils.WebkitToUnix,
                 "expires_utc":ConvertUtils.WebkitToUnix,
                 "last_access_utc":ConvertUtils.WebkitToUnix},
                {"creation_utc":DataTypes.DATE,
                 "expires_utc":DataTypes.DATE,
                 "last_access_utc":DataTypes.DATE})
        ],
        "Favicons": [
            KnownTable("favicon_bitmaps", None,
                {"last_updated":ConvertUtils.WebkitToUnix},
                {"last_updated":DataTypes.DATE })
        ],
        "Shortcuts": [
            KnownTable("omni_box_shortcuts", None,
                {"last_access_time":ConvertUtils.WebkitToUnix},
                {"last_access_time":DataTypes.DATE })
        ],
        "snapshots.db": [
            KnownTable("snapshots", None,
                {"createTime":ConvertUtils.WebkitToUnix},
                {"createTime":DataTypes.DATE })
        ],
	    "Web Data": [
            KnownTable("autofill", None,
                {"date_created":ConvertUtils.WebkitToUnix, 
                 "date_last_used":ConvertUtils.WebkitToUnix},
                {"date_created":DataTypes.DATE, 
                 "date_last_used":DataTypes.DATE}),
            KnownTable("autofill_profiles", None,
                {"date_modified":ConvertUtils.WebkitToUnix },
                {"date_modified":DataTypes.DATE }),
            KnownTable("credit_cards", None,
                {"date_modified":ConvertUtils.WebkitToUnix },
                {"date_modified":DataTypes.DATE }),
            KnownTable("keywords", None,
                {"date_created":ConvertUtils.WebkitToUnix, 
                 "last_modified":ConvertUtils.WebkitToUnix},
                {"date_created":DataTypes.DATE, 
                 "last_modified":DataTypes.DATE}),
            KnownTable("web_intents_defaults", None,
                {"user_date":ConvertUtils.WebkitToUnix },
                {"user_date":DataTypes.DATE })
        ],
	    "SyncData.sqlite3": [
            KnownTable("deleted_metas", None,
                {"mtime":ConvertUtils.JsToUnix, 
                 "server_mtime":ConvertUtils.JsToUnix, 
                 "ctime":ConvertUtils.JsToUnix, 
                 "server_ctime":ConvertUtils.JsToUnix},
                {"mtime":DataTypes.DATE, 
                 "server_mtime":DataTypes.DATE, 
                 "ctime":DataTypes.DATE, 
                 "server_ctime":DataTypes.DATE }),
            KnownTable("metas", None,
                {"mtime":ConvertUtils.JsToUnix, 
                 "server_mtime":ConvertUtils.JsToUnix, 
                 "ctime":ConvertUtils.JsToUnix, 
                 "server_ctime":ConvertUtils.JsToUnix},
                {"mtime":DataTypes.DATE, 
                 "server_mtime":DataTypes.DATE, 
                 "ctime":DataTypes.DATE, 
                 "server_ctime":DataTypes.DATE }),
            KnownTable("share_info", None,
                {"store_birthday":ConvertUtils.JsToUnix, 
                 "db_create_time":ConvertUtils.WebkitToUnix },
                {"store_birthday":DataTypes.DATE, 
                 "db_create_time":DataTypes.DATE })
        ],
        "Archived History": [
            KnownTable("urls", None,
                {"last_visit_time":ConvertUtils.WebkitToUnix},
                {"last_visit_time":DataTypes.DATE }),
            KnownTable("visits", None,
                {"visit_time":ConvertUtils.WebkitToUnix },
                {"visit_time":DataTypes.DATE })
        ],
	    "Network Action Predictor": [
            KnownTable("logged_in_predictor", None,
                {"time":ConvertUtils.WebkitToUnix},
                {"time":DataTypes.DATE })
        ],
	    "Origin Bound Certs": [
            KnownTable("origin_bound_certs", None,
                {"expiration_time":ConvertUtils.WebkitToUnix, 
                 "creation_time":ConvertUtils.WebkitToUnix },
                {"expiration_time":DataTypes.DATE, 
                 "creation_time":DataTypes.DATE })
            ],
	    "snapshots.db": [
            KnownTable("snapshots", None,
                {"createTime":ConvertUtils.WebkitToUnix },
                {"createTime":DataTypes.DATE })
            ],
  }

    def __init__(self):
        self.known = True
        
