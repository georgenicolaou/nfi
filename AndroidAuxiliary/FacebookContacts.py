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


class FacebookContacts(IAuxiliary):
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
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def begin(self):
        self.pq.put("[FacebookContacts]: Scanning contacts")
        store = self.extract_store
        
        contactsdb = store.query_appstore(
                                "com.facebook.orca/databases/contacts_db2")
        if contactsdb == None:
            contactsdb = store.query_appstore(
                                "com.facebook.katana/databases/contacts_db2")
            if contactsdb == None:
                self.selfprint("Error: Facebook not installed")
                return False
            
        if contactsdb.ftype != ExtractStore.TYPE_MULTI:
            self.selfprint("Error: Contacts db not a database")
            return False
        
        contacts = contactsdb.get_multicontent("contacts")
        if contacts == None:
            self.selfprint("Error: Could not locate contacts table")
            return False
        
        if contacts.ctype != ExtractStore.TYPE_TABLE:
            self.selfprint("Error: Contacts table not a table")
            return False
        
        contact_items = []
        for contact in contacts.content:
            contactjson = contact["data"] #column name = "data"
            try:
                cont_obj = json.loads(contactjson)
            except:
                self.selfprint("JSON Error at contact:"+contactjson)
                continue
            contact_info = []
            
            name = "N/A"
            if "name" in cont_obj:
                name = cont_obj["name"]["displayName"]
            contact_info.append(
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Name", 
                    name, 
                    item_name="name" 
                ) 
            )
            
            if "phones" in cont_obj:
                phones = []
                for phone in cont_obj["phones"]:
                    txt = "Not Verified"
                    if phone["isVerified"]: txt = "Verified"
                    phones.append("{}: {} ({})".format( phone["label"], 
                                                phone["displayNumber"], txt ) )
                contact_numbers = ', '.join(phones)
                contact_info.append(
                    ExtractStore.MiscItem( 
                        ExtractStore.TYPE_STRING,
                        "Phone Number(s)",
                        contact_numbers,  
                        item_name="phone_numbers" 
                    ) 
                )
            else:
                contact_info.append(
                    ExtractStore.MiscItem( 
                        ExtractStore.TYPE_STRING, 
                        "Phone Number(s)", 
                        "N/A", 
                        item_name="phone_numbers" 
                    ) 
                )
            
            contact_type = "N/A"
            if "contactType" in cont_obj:
                contact_type = cont_obj["contactType"]
            contact_info.append(
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Type", 
                    contact_type, 
                    item_name="type" 
                ) 
            )
            
            fbid = "N/A"
            if "profileFbid" in cont_obj:
                fbid = cont_obj["profileFbid"]
            contact_info.append(
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, 
                    "Profile ID", 
                    cont_obj["profileFbid"], 
                    item_name="fbid" 
                ) 
            )
                
            contact_items.append(ExtractStore.MiscItem( ExtractStore.TYPE_MULTI, 
                            item_contents=contact_info, item_name="contact" ))
        
        if len(contact_items) == 0: return True
        catalog = store.get_misccatalog( Catalog.CATALOG_COMMS )
        section = catalog.get_section_by_internalname("contacts")
        if section == None:
            section = catalog.get_section( Label("Contacts", "contacts"), True )
        section.add_subsection( 
            ExtractStore.MiscSubSection( 
                Label("Facebook Contacts", "facebook_contacts"), 
                contact_items 
            ) 
        )
        
        
        return True