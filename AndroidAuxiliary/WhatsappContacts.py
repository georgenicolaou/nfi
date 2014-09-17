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

NUMBER_TYPES = {
    19: "Assistant",
    8: "Callback",
    9: "Car",
    10: "Company Main",
    5: "Home Fax",
    4: "Work Fax",
    1: "Home",
    11: "ISDN",
    12: "Main",
    20: "MMS",
    2: "Mobile",
    7: "Other",
    13: "Other Fax",
    6: "Pager",
    14: "Radio",
    15: "Telex",
    16: "TTY TDD",
    3: "Work",
    17: "Work Mobile",
    18: "Work Pager"
}

class WhatsappContacts(IAuxiliary):
   
    name = "WhatsappContacts"
    extract_store = None
    pq = None
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def begin(self):
        self.selfprint("Scanning contacts")
        store = self.extract_store
        subsection_label = Label( "Whatsapp Contacts", "whatsapp_contacts" )
        
        wadb = store.query_appstore( "com.whatsapp/databases/wa.db" )
        if wadb == None:
            self.selfprint("Error: Could not locate database file")
            return False
                
        if wadb.ftype != ExtractStore.TYPE_MULTI:
            self.selfprint("Error: Contacts db not a database")
            return False
        
        contacts = wadb.get_multicontent("wa_contacts")
        if contacts == None:
            self.selfprint("Error: Could not locate contacts table")
            return False
        
        if contacts.ctype != ExtractStore.TYPE_TABLE:
            self.selfprint("Error: contacts table not a table")
            return False
        
        contact_items = []
        for contact in contacts.content:
            phone_type = contact["phone_type"]
            if phone_type in NUMBER_TYPES:
                phone_type = NUMBER_TYPES[phone_type]
            
            isuser = contact["is_whatsapp_user"]
            if isuser == 1:
                isuser = "Yes"
            else:
                isuser = "No"
                
            contact_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Whatsapp Name", 
                    contact["wa_name"], 
                    item_name="wa_name" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Display Name", 
                    contact["display_name"], 
                    item_name="display_name" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Number", 
                    contact["number"], 
                    item_name="number" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Phone Type", 
                    phone_type, 
                    item_name="phone_type" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Whatsapp ID", 
                    contact["jid"], 
                    item_name="jid" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Whatsapp User", 
                    isuser, 
                    item_name="isuser" 
                ),  
            ]
            contact_items.append(ExtractStore.MiscItem( ExtractStore.TYPE_MULTI, 
                            item_contents=contact_info, item_name="contact" ))
        
        if len(contact_items) != 0:
            catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
            section = catalog.get_section( Label("Contacts", "contacts"), True )
            section.add_subsection( ExtractStore.MiscSubSection( 
                                            subsection_label, contact_items ) )
        
        return True