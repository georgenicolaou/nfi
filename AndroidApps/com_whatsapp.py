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

class com_whatsapp(IApp):
    name = "com.whatsapp"
    cname = "Android whatsapp"
    databases = { 
         "wa.db": [ 
                KnownTable("wa_contacts", None, 
                    {"status_timestamp":ConvertUtils.JsToUnix, 
                     "photo_id_timestamp":ConvertUtils.JsToUnix }, 
                    {"status_timestamp":DataTypes.DATE, 
                     "photo_id_timestamp":DataTypes.DATE })
            ],
            "msgstore.db": [         
                KnownTable("chat_list", None, 
                    {"creation":ConvertUtils.JsToUnix },
                    {"creation":DataTypes.DATE }),        
                KnownTable("messages", None, 
                    {"timestamp":ConvertUtils.JsToUnix,  
        		     "received_timestamp":ConvertUtils.JsToUnix,
        		     "send_timestamp":ConvertUtils.JsToUnix, 
        		     "receipt_server_timestamp":ConvertUtils.JsToUnix,
        		     "receipt_device_timestamp":ConvertUtils.JsToUnix },
                    {"timestamp":DataTypes.DATE,
        		     "received_timestamp":DataTypes.DATE,
        		     "send_timestamp":DataTypes.DATE, 
        		     "receipt_server_timestamp":DataTypes.DATE, 
        		     "receipt_device_timestamp":DataTypes.DATE })
            ],
  }

    def __init__(self):
        self.known = True
        
