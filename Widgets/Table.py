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

class Table(IWidget):
    module_id = 3
    module_name = "Table"
    def __init__(self):
        self.default_aspect = 0.7
        self.template = "widget_table.html"
        self.col_size = 6
        self.title = ""
        self.head = []
        self.tblkeyvalue = False
        self.items = []
        return
    
    def _render_widget(self, widget_id, lookup, col_size, title, data):
        tmpl = lookup.get_template(self.template)
        return tmpl.render_unicode(widget_id,col_size,self.default_aspect, 
                                   title, json.dumps(data))
    
    def _render(self, widget_id, lookup):
        tmpl = lookup.get_template(self.template)
        data = {
            "items": self.items,
            "head": self.head,
            "kv": self.tblkeyvalue
        }
        return tmpl.render_unicode(widget_id, self.col_size, self.default_aspect, 
                                   self.title, json.dumps(data))
        
    def add_item(self, item_row ):
        self.items.append(item_row)
    
    def set_header(self, head):
        self.head = head
        
    def set_keyvalue(self,val=True):
        self.tblkeyvalue = val