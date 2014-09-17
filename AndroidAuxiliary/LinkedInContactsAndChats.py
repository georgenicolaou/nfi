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
import json
#import AndroidMisc.Packages as Packages
import ExtractStore


class LinkedInContactsAndChats(IAuxiliary):
    '''
    This module iterates through all applications and identifies additional
    permissions that haven't been defined in packages.xml but do exist as part
    of individual application permissions. This includes standard default
    system Android permissions such as com.android.INTERNET.
    
    This module uses information collected in the Catalog plugin and generates
    information within the same plugin. 
    '''
    name = "LinkedInContactsAndChats"
    extract_store = None
    pq = None
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def begin(self):
        self.selfprint("Scanning contacts")
        store = self.extract_store
        
        contactsdb = store.query_appstore( 
                                "com.linkedin.android/databases/linkedin.db" )
        if contactsdb == None:
            self.selfprint("Error: Could not locate database file")
            return False
                
        if contactsdb.ftype != ExtractStore.TYPE_MULTI:
            self.selfprint("Error: Contacts db not a database")
            return False
        
        contacts = contactsdb.get_multicontent("connections")
        if contacts == None:
            self.selfprint("Error: Could not locate connections table")
            return False
        
        if contacts.ctype != ExtractStore.TYPE_TABLE:
            self.selfprint("Error: connections table not a table")
            return False
        
        contact_items = []
        for contact in contacts.content:
            
            contact_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Name", 
                    contact["display_name"], 
                    item_name="name" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Headline", 
                    contact["headline"], 
                    item_name="headline" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "LinkedIn Member ID", 
                    contact["member_id"], 
                    item_name="member_id" 
                ),
            ]
            contact_items.append(ExtractStore.MiscItem( ExtractStore.TYPE_MULTI, 
                            item_contents=contact_info, item_name="contact" ))
        
        if len(contact_items) != 0:
            catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
            section = catalog.get_section_by_internalname("contacts")
            if section == None:
                section = catalog.get_section( Label("Contacts", "contacts"), 
                                               True )
            section.add_subsection( 
                ExtractStore.MiscSubSection( 
                    Label("LinkedIn Connections", "linkedin_connections"), 
                    contact_items 
                ) 
            )
        
        self.selfprint("Retrieving Messages")
        messages = contactsdb.get_multicontent("messages")
        if messages == None or len(messages.content) == 0:
            self.selfprint("None or empty LinkedIn Messages")
        message_items = []
        for message in messages.content:
            message_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Date", 
                    message["timestamp"], 
                    item_name="date" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "From", 
                    message["from_display_name"], 
                    item_name="from" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Subject", 
                    message["subject"], 
                    item_name="subject" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Partial Message", 
                    message["body"], 
                    item_name="partial_message" 
                ),
            ]
            message_items.append(
                ExtractStore.MiscItem(
                    ExtractStore.TYPE_MULTI,
                    item_contents=message_info,
                    item_name="message"
                )
            )
        
        if len(message_items) != 0:
            self.selfprint("Populating LinkedIn Messages section")
            catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
            section = catalog.get_section( Label( "Internet Chats", 
                                                  "internet_chats" ), True )
            section.add_subsection(
                ExtractStore.MiscSubSection(
                    Label("LinkedIn Messages", "linkedin_messages"),
                    message_items
                )
            )
        return True