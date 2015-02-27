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
import Catalog
from IAuxiliary import IAuxiliary
from AndroidMisc import Packages, UsageStats
#import AndroidMisc.Packages as Packages
import ExtractStore


class _AppInfo(object):
    def __init__(self):
        self.name = ""
        self.codePath = ""
        self.flags = 0
        self.ft = 0
        self.it = 0
        self.ut = 0
        self.version = 0
        self.uid = 0
        self.installer = ""
        self.permissions = []
        self.last_run = None
        self.exec_history = {}
    
class ApplicationMiscParser(IAuxiliary):
    extract_store = None
    pq = None
    name = "ApplicationMiscParser"
    
    def __init__(self, extract_store, print_queue):
        self.extract_store = extract_store
        self.pq = print_queue
    
    def get_usage_statistics(self):
        cat = self.extract_store.get_misccatalog( 
                                        UsageStats.UsageStats.catalog_id )
        if cat == None: return None
        
        section = cat.get_section( UsageStats.UsageStats.title )
        if section == None: return None
        
        subsection = section.get_subsection("usage_stats")
        if subsection == None: return None
        
        #Parsing usage stats in a friendlier shape.
        stats_list = {}
        for stat in subsection.subsection_items:
            name = stat.get_subvaluebyname("activity_name")
            lrt = stat.get_subvaluebyname("last_run")
            if name == None or lrt == None: continue
            if name in stats_list:
                stats_list[name].append(lrt)
            else:
                stats_list[name] = [lrt] 
        return stats_list
    
    def set_application_usagestats(self, appinfo, usage_stats):
        relevant_stats = {}
        for intent,lrt in usage_stats.iteritems():
            if intent.startswith(appinfo.name):
                relevant_stats[intent] = lrt
        
        return
           
    def begin(self):
        self.selfprint("Scanning packages")
        subs = self.extract_store.query_catalog( Packages.Packages.catalog_id, 
                                                 "packages.installed_apps")
        if subs == None:
            self.selfprint("[Error]: Crucial packages catalog could not be " +
                           "populated, please open an issue on github along " +
                           "with information about the device you are scanning")
            return False
        
        if len(subs.subsection_items) == 0:
            self.selfprint("[WANRING] Empty packages list")
            return False
        
        self.selfprint("Found: {} packages".format(
                            len(subs.subsection_items)))
        usage_stats = self.get_usage_statistics()
        for app in subs.subsection_items:
            appinfo = _AppInfo()
            if app.item_type != ExtractStore.TYPE_MULTI:
                self.selfprint("[ERROR] Not an array")
                continue
            for field in app.item_contents:
                if field.item_type != ExtractStore.TYPE_MULTI:
                    setattr( appinfo, field.item_name, field.item_value )
                else:
                    #Array field, this should be permissions
                    for perm_item in field.item_contents:
                        perm = perm_item.item_value
                        #perm = perm_item.item_contents[0].item_value
                        appinfo.permissions.append(perm)
            #Time to modify application
            if usage_stats != None:
                for intent,lrt_list in usage_stats.iteritems():
                    if intent.startswith(appinfo.name):
                        for lrt in lrt_list:
                            if lrt in appinfo.exec_history:
                                appinfo.exec_history[lrt].append(intent)
                            else:
                                appinfo.exec_history[lrt] = [intent]
            
            if len(appinfo.exec_history) != 0:
                appinfo.last_run = sorted(appinfo.exec_history.keys())[-1]
            
            #self.set_application_usagestats(appinfo, usage_stats)
            ret = self._update_app_info(appinfo)
            if ret == False:
                self.selfprint( "Could not find APP {}".format(appinfo.name) )
        return True
        
    def _get_application_cname(self, binary_path ):
        return
    
    def _update_app_info(self, appinfo):
        app = self.extract_store.find_application(appinfo.name)
        if app == None: return False
        app.permissions = appinfo.permissions
        app.installation_date = appinfo.it
        app.update_date = appinfo.ut
        app.version = appinfo.version
        app.binary = appinfo.codePath
        app.app_user = appinfo.uid
        app.installer = appinfo.installer
        app.last_run = appinfo.last_run
        if len(appinfo.exec_history) != 0:
            app.exec_history = appinfo.exec_history
        
        
