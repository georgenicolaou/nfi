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


class SkypeChats(IAuxiliary):
   
    name = "SkypeChats"
    extract_store = None
    pq = None
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    SKYPE_STATUS = {
        1: "Pending",
        2: "Delivered",
        4: "Received",
    }
    
    SKYPE_MSGTYPE = {
        61: "Chat",
        60: "/me Message",
        68: "File Transfer",
        30: "Call Start",
        39: "Call End",
        10: "Person Added",
        13: "Person Left"
    }
    def begin(self):
        self.selfprint("Scanning messages")
        store = self.extract_store
        ok = False
        
        subsection_label = Label( "Skype Messages", "skype_messages" )
        
        skypefiles = store.query_appstore( "com.skype.raider/files" )
        if skypefiles == None:
            self.selfprint("Error: No Skype files found")
            return False
        
        maindbs = skypefiles.find_all_files("main.db")
        if maindbs == None:
            self.selfprint("Error: Could not find main.db")
            return False
        
        message_items = []
        for maindb in maindbs:
            accnt = maindb.get_multicontent("Accounts", ExtractStore.TYPE_TABLE)
            if accnt == None:
                self.selfprint("No account table found, treating as unknown")
                accnt_name = "Unknown Account"
            else:
                accnt_name = accnt.content[0]['skypename']
            
            messages = maindb.get_multicontent("Messages", 
                                               ExtractStore.TYPE_TABLE)
            if messages == None:
                self.selfprint("Messages table not found")
                continue
            
            
            for msg in messages.content:
                if msg['chatmsg_status'] in self.SKYPE_STATUS:
                    status = self.SKYPE_STATUS[msg['chatmsg_status']]
                else:
                    status = msg['chatmsg_status']
                
                if msg['type'] in self.SKYPE_MSGTYPE:
                    msgtype = self.SKYPE_MSGTYPE[msg['type']]
                else:
                    msgtype = msg['type']
                    
                msg_info = [
                    ExtractStore.MiscItem(
                        ExtractStore.TYPE_STRING, "Account", 
                        accnt_name, 
                        item_name="account" 
                    ),
                    ExtractStore.MiscItem(
                        ExtractStore.TYPE_DATE, "Date", 
                        msg['timestamp'], 
                        item_name="date" 
                    ),
                    ExtractStore.MiscItem(
                        ExtractStore.TYPE_STRING, "Type", 
                        msgtype, 
                        item_name="type" 
                    ),
                    ExtractStore.MiscItem(
                        ExtractStore.TYPE_STRING, "Status", 
                        status, 
                        item_name="status" 
                    ),
                    ExtractStore.MiscItem(
                        ExtractStore.TYPE_STRING, "From", 
                        u"{} ({})".format(msg['from_dispname'],msg['author']), 
                        item_name="from" 
                    ),
                    ExtractStore.MiscItem(
                        ExtractStore.TYPE_STRING, "Message", 
                        msg["body_xml"], 
                        item_name="message" 
                    ),
                ]
                message_items.append(
                    ExtractStore.MiscItem( ExtractStore.TYPE_MULTI, 
                                item_contents=msg_info, item_name="message" )
                )
                    
        if len(message_items) != 0:
            catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
            section = catalog.get_section( Label("Internet Chats", 
                                                 "internet_chats"), True )
            section.add_subsection( ExtractStore.MiscSubSection( 
                                            subsection_label, message_items ) )
            ok = True
        
        return ok