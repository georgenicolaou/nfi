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
from IAuxiliary import IAuxiliary
from IMiscSource import Label
from Catalog import Catalog
from AndroidMisc import Packages, UsageStats
#import AndroidMisc.Packages as Packages
import ExtractStore
import ConvertUtils
import json


class FacebookMessages(IAuxiliary):
    '''
    This module iterates through all applications and identifies additional
    permissions that haven't been defined in packages.xml but do exist as part
    of individual application permissions. This includes standard default
    system Android permissions such as com.android.INTERNET.
    
    This module uses information collected in the Catalog plugin and generates
    information within the same plugin. 
    '''
    name = "FacebookContacts"
    extract_store = None
    pq = None
    
    fb_message_types = {
        -1: "BEFORE_FIRST_SENTINEL",
        0: "REGULAR",
        1: "ADD_MEMBERS",
        2: "REMOVE_MEMBERS",
        3: "SET_NAME",
        4: "SET_IMAGE",
        5: "VIDEO_CALL",
        6: "MISSED_VIDEO_CALL",
        7: "REMOVED_IMAGE",
        100: "INCOMING_CALL",
        101: "MISSED_CALL",
        102: "OUTGOING_CALL",
        900: "PENDING_SEND",
        901: "FAILED_SEND",
        1000: "UNKNOWN"
    } 
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def _get_msgtype(self,msgtype):
        if type(msgtype) != int:
            if type(msgtype) in [str, unicode]:
                msgtype = int(msgtype)
            else:
                return "Unknown"
        if msgtype in self.fb_message_types:
            return self.fb_message_types[msgtype]
        return "Unknown"
    
    def _parse_db(self,threadsdb):
        if threadsdb.ftype != ExtractStore.TYPE_MULTI:
            self.selfprint("Error: Contacts db not a database")
            return False
        
        messages = threadsdb.get_multicontent("messages")
        if messages == None:
            self.selfprint("Error: Could not locate messages table")
            return False
        if messages.ctype != ExtractStore.TYPE_TABLE:
            self.selfprint("Error: messages table not a table")
            return False
        
        message_items = []
        for message in messages.content:
            unixtime = message["timestamp_ms"] #ConvertUtils.JsToUnix(message["timestamp_ms"])
            senderjson = message["sender"]
            if senderjson == None:
                sender = "N/A"
            else:
                try:
                    sender_obj = json.loads(senderjson)
                    sender = sender_obj["name"]
                except:
                    sender = "Error"
                    pass
            text = message["text"]
            msgtype = self._get_msgtype(message["msg_type"])
            
            attachments = message["attachments"]
            if attachments != None:
                try:
                    att_obj = json.loads(attachments)
                    if type(att_obj) != list:
                        attachments = "None"
                    elif len(att_obj) == 0:
                        attachments = "None"
                    else:
                        attachments = ', '.join([ att["mime_type"] for att in att_obj ])
                except:
                    attachments = "Error"
            else:
                attachments = "None"
                
            message_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, 
                    "Date", 
                    unixtime, 
                    item_name="date" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Sender", 
                    sender, 
                    item_name="sender" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Type", 
                    msgtype, 
                    item_name="type" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Attachments", 
                    attachments, 
                    item_name="attachments" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Text", 
                    text, 
                    item_name="text" 
                ),
            ]
            message_items.append(
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_MULTI, 
                    item_contents=message_info, 
                    item_name="message")
            )
        return message_items
    
    def _gensubsection(self, catalog, section_label, subsection_label, 
                       threadsdb):
        subsection = ExtractStore.MiscSubSection( subsection_label, [] )
        message_items = self._parse_db(threadsdb)
        if message_items == False: return False
        if len(message_items) != 0:
            subsection.add_items(message_items)
            section = catalog.get_section( section_label, True )
            section.add_subsection(subsection)
            return True
        return False
            
    def begin(self):
        ok = False
        self.pq.put("[FacebookContacts]: Scanning contacts")
        store = self.extract_store
        catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
        section_label = Label("Internet Chats", "internet_chats")
        threadsdb = store.query_appstore(
                                "com.facebook.orca/databases/threads_db2")
        
        if threadsdb != None:
            ok = self._gensubsection(catalog, section_label, 
                Label("Facebook Messenger Chats", "facebook_messenger_chats"), 
                threadsdb)
        
        threadsdb = store.query_appstore(
                                "com.facebook.katana/databases/threads_db2")
        if threadsdb != None:
            ok = self._gensubsection(catalog, section_label, 
                Label("Facebook App Chats", "facebook_messenger_chats"), 
                threadsdb)

        return ok