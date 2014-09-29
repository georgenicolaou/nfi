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
import cherrypy, ExtractStore #HtmlExtract, json, re, base64
from Catalog import Catalog
from Timeline import Timeline, TimelineDate, TimelineItem

class TimelinePlugin(IMainModule):
    TIMELINE_PLUGIN = 1
    
    name = "Timeline"
    internal_name = "timeline"
    
    _menu = [
        MenuEntry( "View Timeline", "/view", "fa-archive" ),
    ]
    
    def get_menuentry_list(self, store, case_id):
        menu = []
        for entry in self._menu:
            case_entry = MenuEntry( entry.name, entry.link+"/"+str(case_id), 
                                    entry.icon)
            menu.append(case_entry)
        return menu
    
    def __init__(self, lookup, case, settings):
        '@type lookup: mako.lookup.TemplateLookup'
        self.lookup = lookup
        self.case = case
        self.settings = settings
        return
    
    def set_templatelookup(self, lookup):
        '@type lookup: mako.lookup.TemplateLookup'
        self.lookup = lookup
    @cherrypy.expose
    def get(self,case_id,start,end):
        print "{} - {}".format(start,end)
        store = self.case.get_store(case_id)
        timeline = store.timeline
        items = timeline.get_items(start,end)
        tmpl = self.lookup.get_template("timeline_list.html")
        return tmpl.render_unicode(items)    
    @cherrypy.expose
    def view(self,case_id):
        tmpl = self.lookup.get_template("timeline_1.html")
        return tmpl.render_unicode("Events Timeline",self, case_id )