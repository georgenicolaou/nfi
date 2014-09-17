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
from IWidget import IWidget
import json

class PieChart(IWidget):
    module_id = 1
    module_name = "Pie Chart"
    def __init__(self):
        self.default_aspect = 0.7
        self.template = "widget_pie.html"
        self.col_size = 6
        self.data = []
        self.sort = "value-desc"
        self.title = ""
        self.hideperc = None
        self.display_value = False
        return
    
    def _render_widget(self, widget_id, lookup, col_size, title, data):
        tmpl = lookup.get_template(self.template)
        return tmpl.render_unicode(widget_id,col_size,self.default_aspect, 
                                   title, json.dumps(data))
    
    def _render(self, widget_id, lookup):
        """
        "smallSegmentGrouping": {
            "enabled": true,
            "value": 5
        },
        """
        tmpl = lookup.get_template(self.template)
        data = {
            "data":{
                "sortOrder": self.sort,
                "content": self.data
            }
        }
        if self.hideperc != None:
            data["data"]["smallSegmentGrouping"] = {
                "enabled":"true", 
                "value": self.hideperc
            }
        if self.display_value:
            data["labels"] = { "inner": { "format": "value" } }
        return tmpl.render_unicode(widget_id, self.col_size, self.default_aspect, 
                                   self.title, json.dumps(data))
        
    def add_item(self, label, value, color=None):
        if value == 0: return
        item = {"label":label,"value":value}
        if color != None:
            item["color"] = color
        self.data.append(item)
    
    def make_asc(self):
        self.sort = "value-asc"
        
    def make_desc(self):
        self.sort = "value-desc"
        
    def set_hideperc(self,perc):
        self.hideperc = perc
        
    def set_display_values(self, val):
        if type(val) != bool: return
        self.display_value = val