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
from IMainModule import MenuEntry, IMainModule
import cherrypy

class Catalog(IMainModule):
    CATALOG_NONE = 0
    CATALOG_DEVINFO = 1
    CATALOG_SETTINGS = 2
    CATALOG_APPS = 3
    CATALOG_NETWORKING = 4
    CATALOG_LOGS = 5
    CATALOG_TIMELINE = 6
    CATALOG_COMMS = 7
    
    name = "Catalogs"
    internal_name = "catalog"
    
    catalogs_info = {
        CATALOG_NONE : { "name":"Uncategorised", "display":False },
        CATALOG_DEVINFO : {"name": "Device Info", "display": True, 
                        "url": "/devinfo", "icon": "fa-info" },
        CATALOG_SETTINGS : { "name": "Device Settings", "display": False, 
                            "url": "/devsettings", "icon": "fa-gear" },
        CATALOG_APPS : { "name": "Apps", "display": True, "url": "/apps", 
                        "icon": "fa-archive" },
        CATALOG_NETWORKING : { "name": "Networking", "display": True, 
                              "url": "/devnet", "icon": "fa-globe" },
        CATALOG_LOGS : { "name": "Device Logs", "display": True, 
                        "url": "/logs", "icon": "fa-file" },
        CATALOG_TIMELINE : { "name": "Timeline", "display": False, 
                            "url": "/timeline", "icon": "fa-clock-o" },
        CATALOG_COMMS : { "name": "Communications", "display":True, 
                         "url": "/comms", "icon":"fa-comments-o" }
    }
    
    def __init__(self, lookup, case, settings):
        '@type lookup: mako.lookup.TemplateLookup'
        self.lookup = lookup
        self.case = case
        self.settings = settings
        return
    
    
    def set_templatelookup(self, lookup):
        '@type lookup: mako.lookup.TemplateLookup'
        self.lookup = lookup
        
    def get_menuentry_list(self, store, case_id):
        menu = []
        for cat_id, catalog in self.catalogs_info.iteritems():
            if catalog['display'] == False: continue
            store_catalog = store.get_misccatalog(cat_id)
            if len(store_catalog.sections) != 0:
                entry = MenuEntry(catalog['name'], "#", catalog['icon'] )
                for section in store_catalog.sections.values():
                    child = MenuEntry( section.section_label, catalog['url'] + 
                                       '/' + str(case_id) + '/' +
                                       section.section_name )
                    entry.content.append(child)
            else:
                entry = MenuEntry(catalog['name'], 
                                  catalog['url']+'/'+str(case_id),
                                  catalog['icon'])
            menu.append(entry)
        return menu

    def get_catalog_table_html(self,catalog,section_name):
        tmpl = self.lookup.get_template("catalog_table.html")
        for name,section in catalog.sections.iteritems():
            if( name.replace(' ', '') == section_name ):
                return tmpl.render_unicode(section=section)
        tmpl = self.lookup.get_template("error.html")
        return tmpl.render_unicode(error="Catalog not found")
    
    @cherrypy.expose
    def apps(self, case_id, section_name):
        cat = self.case.get_store(case_id).get_misccatalog(Catalog.CATALOG_APPS)
        return self.get_catalog_table_html(cat,section_name)
    
    @cherrypy.expose
    def devinfo(self, case_id, section_name):
        cat = self.case.get_store(case_id).get_misccatalog(
                                                        Catalog.CATALOG_DEVINFO)
        return self.get_catalog_table_html(cat, section_name)
    
    @cherrypy.expose
    def logs(self, case_id, section_name):
        cat = self.case.get_store(case_id).get_misccatalog(Catalog.CATALOG_LOGS)
        return self.get_catalog_table_html(cat, section_name)
    
    @cherrypy.expose
    def devnet(self, case_id, section_name):
        cat = self.case.get_store(case_id).get_misccatalog(
                                                    Catalog.CATALOG_NETWORKING)
        return self.get_catalog_table_html(cat, section_name)
        
    @cherrypy.expose
    def comms(self, case_id, section_name):
        cat = self.case.get_store(case_id).get_misccatalog(
                                                        Catalog.CATALOG_COMMS)
        return self.get_catalog_table_html(cat, section_name)
                
        
        