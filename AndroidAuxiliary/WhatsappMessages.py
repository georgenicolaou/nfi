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


class WhatsappMessages(IAuxiliary):
   
    name = "WhatsappMessages[Needs Update]"
    extract_store = None
    pq = None
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def begin(self):
        self.selfprint("Scanning messages")
        store = self.extract_store
        subsection_label = Label( "Whatsapp Messages", "whatsapp_messages" )
        
        msgsdb = store.query_appstore( "com.whatsapp/databases/msgstore.db" )
        if msgsdb == None:
            self.selfprint("Error: Could not locate database file")
            return False
                
        if msgsdb.ftype != ExtractStore.TYPE_MULTI:
            self.selfprint("Error: Messages db not a database")
            return False
        
        msgs = msgsdb.get_multicontent("messages")
        if msgs == None:
            self.selfprint("Error: Could not locate messages table")
            return False
        
        if msgs.ctype != ExtractStore.TYPE_TABLE:
            self.selfprint("Error: messages table not a table")
            return False
        
        message_items = []
        for msg in msgs.content: #XXX need to add more columns
            msg_info = [
                ExtractStore.MiscItem( #XXX need to convert this
                    ExtractStore.TYPE_STRING, "Origin", 
                    msg["origin"], 
                    item_name="wa_name" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Send Date", 
                    msg["send_timestamp"], 
                    item_name="send_timestamp" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Received Date", 
                    msg["received_timestamp"], 
                    item_name="received_timestamp" 
                ),
                ExtractStore.MiscItem( #XXX need to convert this
                    ExtractStore.TYPE_STRING, "Status", 
                    msg["status"], 
                    item_name="status" 
                ),
                ExtractStore.MiscItem( #XXX need to join Message/Raw Message
                    ExtractStore.TYPE_STRING, "Message", 
                    msg["data"], 
                    item_name="data" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Raw Message", 
                    msg["raw_data"], 
                    item_name="raw_data" 
                ),
            ]
            message_items.append(ExtractStore.MiscItem( ExtractStore.TYPE_MULTI, 
                            item_contents=msg_info, item_name="message" ))
        
        if len(message_items) != 0:
            catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
            section = catalog.get_section( Label("Internet Chats", 
                                                 "internet_chats"), True )
            section.add_subsection( ExtractStore.MiscSubSection( 
                                            subsection_label, message_items ) )
        
        return True