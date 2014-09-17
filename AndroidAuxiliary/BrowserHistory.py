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


class BrowserHistory(IAuxiliary):
   
    name = "BrowserHistory"
    extract_store = None
    pq = None
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def scan_com_android_chrome(self,store):
        appfiles = store.query_appstore("com.android.chrome/app_chrome")
        if appfiles == None:
            self.selfprint("Error: Chrome files directory not found")
            return False
        historydb = appfiles.find_file_recursieve("History")
        if historydb == None:
            self.selfprint("Error: History database not found")
            return False
        
        #XXX we should create an application module for this to join tables
        #    like we are doing here
        urls = historydb.get_multicontent("urls", ExtractStore.TYPE_TABLE)
        if urls == None:
            self.selfprint("Error: could not find chrome urls table")
            return False
        
        urldict = {}
        for url in urls.content:
            urldict[url['id']] = {
                "visits": url['visit_count'],
                "title": url['title'],
                "url": url['url'],
            }
        
        visits = historydb.get_multicontent("visits", ExtractStore.TYPE_TABLE)
        if visits == None:
            self.selfprint("Error: could not find chrome visits table")
            return False
        
        visit_items = []
        for visit in visits.content:
            date = visit['visit_time']
            duration = visit['visit_duration']
            if visit['url'] in urldict:
                visitinfo = urldict[visit['url']]
                num_visits = visitinfo['visits']
                title = visitinfo['title']
                url = visitinfo['url']
            else:
                num_visits = "N/A"
                title = "N/A"
                url = "N/A ({})".format(visit['url'])

            visit_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Date", 
                    date, 
                    item_name="date" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Browser", 
                    "Chrome Browser", 
                    item_name="browser" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "# Visits", 
                    num_visits, 
                    item_name="visits" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Duration", 
                    duration, 
                    item_name="duration" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Title", 
                    title, 
                    item_name="title" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "URL", 
                    url, 
                    item_name="url" 
                ),
            ]
                
            visit_items.append( 
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_MULTI, 
                    item_contents=visit_info, 
                    item_name="visit" 
                ) 
            )
        return visit_items
            
              
        
    def scan_com_android_browser(self, store):
        browser2db = store.query_appstore(
                                    "com.android.browser/databases/browser2.db")
        if browser2db == None:
            self.selfprint("Error: could not located com.android.browser db")
            return False
        
        historytbl = browser2db.get_multicontent( "history", 
                                                  ExtractStore.TYPE_TABLE)
        if historytbl == None:
            self.selfprint("Error: issue loading history table")
            return False
        
        visit_items = []
        for visit in historytbl.content:
            visit_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Date", 
                    visit["date"], 
                    item_name="date" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Browser", 
                    "Android Browser", 
                    item_name="browser" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "# Visits", 
                    visit["visits"], 
                    item_name="visits" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Duration", 
                    "N/A", 
                    item_name="duration" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Title", 
                    visit["title"], 
                    item_name="title" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "URL", 
                    visit["url"], 
                    item_name="url" 
                ),
            ]
            
            visit_items.append( 
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_MULTI, 
                    item_contents=visit_info, 
                    item_name="visit" 
                ) 
            )
        return visit_items
    
    def scan_firefox_browser(self, store):
        appfiles = store.query_appstore("org.mozilla.firefox/files/mozilla")
        if appfiles == None:
            self.selfprint("Error: Mozilla files directory not found")
            return False
        
        browserdb = appfiles.find_file_recursieve("browser.db")
        if browserdb == False:
            self.selfprint("Error: browser database not found")
            return False
        
        historytbl = browserdb.get_multicontent("history",
                                                ExtractStore.TYPE_TABLE)
        if historytbl == None:
            self.selfprint("Error: could not find history table")
            return False
        
        visit_items = []
        for visit in historytbl.content:
            visit_info = [
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_DATE, "Date", 
                    visit["date"], 
                    item_name="date" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Browser", 
                    "Mozilla Firefox", 
                    item_name="browser" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "# Visits", 
                    visit["visits"], 
                    item_name="visits" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Duration", 
                    "N/A", 
                    item_name="duration" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "Title", 
                    visit["title"], 
                    item_name="title" 
                ),
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_STRING, "URL", 
                    visit["url"], 
                    item_name="url" 
                ),
            ]
            
            visit_items.append( 
                ExtractStore.MiscItem( 
                    ExtractStore.TYPE_MULTI, 
                    item_contents=visit_info, 
                    item_name="visit" 
                ) 
            )
        return visit_items    
        
    def begin(self):
        self.selfprint("Consolidating browser history from browser Apps")
        store = self.extract_store
        section_label = Label("Internet Browsing", "internet_browsing" )
        subsection_label = Label( "Browser History", "browser_history" )
        
        ok = False
        
        total_visits = []
        browserfunc = [
            self.scan_com_android_browser,
            self.scan_com_android_chrome
        ]
        
        for func in browserfunc:
            visits = func(store)
            if visits != False:
                total_visits += visits
                ok = True
        
        if len(total_visits) != 0:
            catalog = store.get_misccatalog( Catalog.CATALOG_NETWORKING )
            section = catalog.get_section( section_label, True )
            section.add_subsection( ExtractStore.MiscSubSection( 
                                            subsection_label, total_visits ) )
        else:
            ok = False
        return ok