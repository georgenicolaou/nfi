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

class com_android_providers_contacts(IApp):
    name = "com.android.providers.contacts"
    cname = "Contacts Provider"
    databases = { 
        "contacts2.db": [ 
            KnownTable("_sync_state", None, None, {"data": DataTypes.DATA}),
            KnownTable("data", None, None, { "data15": DataTypes.DATA }),
            KnownTable("contacts", None,
                {"contact_last_updated_timestamp": ConvertUtils.JsToUnix, #18
                 "last_time_contacted": ConvertUtils.JsToUnix}, #15
                {"contact_last_updated_timestamp": DataTypes.DATE,
                 "last_time_contacted": DataTypes.DATE}),
            KnownTable("deleted_contacts", None, #18
                {"contact_deleted_timestamp":ConvertUtils.JsToUnix},
                {"contact_deleted_timestamp": DataTypes.DATE}),
            KnownTable("raw_contacts", None,
                {"last_time_contacted": ConvertUtils.JsToUnix}, #15 
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("calls", None,
                {"date":ConvertUtils.JsToUnix},
                {"date": DataTypes.DATE}),
            KnownTable("data_usage_stat", None, 
                {"last_time_used":ConvertUtils.JsToUnix}, 
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_raw_contacts", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_contacts", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_entities", None,
                {"contact_last_updated_timestamp":ConvertUtils.JsToUnix},
                {"contact_last_updated_timestamp": DataTypes.DATE}),
            KnownTable("view_data_usage_stat", None,
                {"last_time_used":ConvertUtils.JsToUnix},
                {"last_time_used": DataTypes.DATE}),
            KnownTable("view_v1_people", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_v1_contact_methods", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted":DataTypes.DATE}),
            KnownTable("view_v1_phones", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted":DataTypes.DATE})
        ],
        "profile.db": [
            KnownTable("_sync_state", None, None, {"data": DataTypes.DATA}),
            KnownTable("data", None, None, { "data15": DataTypes.DATA }),
            KnownTable("contacts", None,
                {"contact_last_updated_timestamp": ConvertUtils.JsToUnix, #18
                 "last_time_contacted": ConvertUtils.JsToUnix}, #15
                {"contact_last_updated_timestamp": DataTypes.DATE,
                 "last_time_contacted": DataTypes.DATE}),
            KnownTable("deleted_contacts", None, #18
                {"contact_deleted_timestamp":ConvertUtils.JsToUnix},
                {"contact_deleted_timestamp": DataTypes.DATE}),
            KnownTable("raw_contacts", None,
                {"last_time_contacted": ConvertUtils.JsToUnix}, #15 
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("calls", None,
                {"date":ConvertUtils.JsToUnix},
                {"date": DataTypes.DATE}),
            KnownTable("data_usage_stat", None, 
                {"last_time_used":ConvertUtils.JsToUnix}, 
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_raw_contacts", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_contacts", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_entities", None,
                {"contact_last_updated_timestamp":ConvertUtils.JsToUnix},
                {"contact_last_updated_timestamp": DataTypes.DATE}),
            KnownTable("view_data_usage_stat", None,
                {"last_time_used":ConvertUtils.JsToUnix},
                {"last_time_used": DataTypes.DATE}),
            KnownTable("view_v1_people", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted": DataTypes.DATE}),
            KnownTable("view_v1_contact_methods", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted":DataTypes.DATE}),
            KnownTable("view_v1_phones", None,
                {"last_time_contacted":ConvertUtils.JsToUnix},
                {"last_time_contacted":DataTypes.DATE})
        ]
    }
    def __init__(self):
        self.known = True

