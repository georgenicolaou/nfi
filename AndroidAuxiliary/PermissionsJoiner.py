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
from Catalog import Catalog
from AndroidMisc import Packages, UsageStats
#import AndroidMisc.Packages as Packages
import ExtractStore


class PermissionsJoiner(IAuxiliary):
    '''
    This module iterates through all applications and identifies additional
    permissions that haven't been defined in packages.xml but do exist as part
    of individual application permissions. This includes standard default
    system Android permissions such as com.android.INTERNET.
    
    This module uses information collected in the Catalog plugin and generates
    information within the same plugin. 
    '''
    extract_store = None
    pq = None
    name = "PermissionsJoiner"
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def begin(self):
        self.pq.put("[PermissionsJoiner]: Scanning permissions")
        
        store = self.extract_store
        cat = store.get_misccatalog( Catalog.CATALOG_APPS )
        
        sub_apps = store.query_catalog( Catalog.CATALOG_APPS, 
                                        "packages.installed_apps")
        if sub_apps == None:
            self.pq.put("[PermissionsJoiner]: Could not find installed_apps" +
                        " subsection.")
            return False
        sub_permissions = store.query_catalog( Catalog.CATALOG_APPS, 
                                        "packages.available_permissions")
        if sub_permissions == None:
            self.pq.put("[PermissionsJoiner]: Could not find " +
                        "available_permissions subsection")
            return False
        known_perm = []
        new_perm = []
        for perm_container in sub_permissions.subsection_items:
            known_perm.append( perm_container.get_subvaluebyname("name") )
        
        for app_container in sub_apps.subsection_items:
            for item in app_container.item_contents:
                if item.item_type == ExtractStore.TYPE_MULTI:
                    perm = item.get_subvaluebyname("name")
                    if perm not in known_perm and perm not in new_perm:
                        new_perm.append(perm)
        
        item_perm = []
        for perm in new_perm:
            perm_container = ExtractStore.MiscItem( ExtractStore.TYPE_MULTI )
            perm_container.add_multiple_items([
                ExtractStore.MiscItem( ExtractStore.TYPE_STRING, "Name", perm, 
                                       item_name="name"),
                ExtractStore.MiscItem( ExtractStore.TYPE_STRING, "Package", 
                                       "N/A", item_name="package" ),
                ExtractStore.MiscItem( ExtractStore.TYPE_STRING, "Protection", 
                                       "N/A", item_name="protection" )
            ])
            item_perm.append(perm_container)
        
        sub_permissions.add_items( item_perm )
        return True